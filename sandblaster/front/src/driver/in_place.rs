//! In-place lifted modules (DESIGN.md §2.1 "in place", SEMANTICS.md §19.5):
//! `sandblaster::build::compile_lifted(root, name)` verifies a DSL root whose
//! lifted exec modules are the host crate's own files
//! (`#[lift(in_place)] #[path = "../../src/x.rs"] mod x;`). The build
//! writes the record `OUT_DIR/<name>-verified.txt` (which files, their
//! hashes, the instances, what stays unchecked host code, the host
//! obligations), `OUT_DIR/<name>-report.json` and `-timing.json`, and the
//! **lowered copy** of every in-place file (below).
//!
//! Checks before verification:
//!
//! 1. `name` is a lowercase identifier;
//! 2. the DSL root is not under `src/` (its laws and proofs are not host code);
//! 3. every in-place lifted file is under `src/` — it must be host source;
//! 4. the host file that declares each in-place module declares it so that
//!    rustc compiles what was verified ([`declaration`]; the file has no
//!    `#[path]` attribute): as `mod <m>;` (rustc compiles the file as
//!    written), or by its **lowered declaration** (rustc compiles the
//!    build's lowered copy of the file):
//!
//!    ```text
//!    pub mod iterator {
//!        //! (the leading `//!` lines of iterator.rs, exactly)
//!        include!(concat!(env!("OUT_DIR"), "/mmr-lowered__merkle__mmr__iterator.rs"));
//!    }
//!    ```
//!
//!    The copy's name must be this build's (`<name>-lowered__<path under
//!    src/, `/` as `__`>`), the docs the source's (an `include!`d file cannot
//!    carry inner docs), and the source includable ([`not_includable`]: no
//!    inner attribute after its docs, no out-of-line `mod`, no `file!`,
//!    `line!`, `column!` or `include*!`). The lift reads a lowered
//!    declaration of a lifted child as `mod <m>;`
//!    (`crate::lift::open::lowered_include`), so the verified source is the
//!    file itself; any other inline module that includes something is
//!    refused, by the lift (a lifted file) or here (the declaring file);
//! 5. no file under `src/` mentions `"/<name>-lowered__` except the
//!    lowered declarations, once each.
//!
//! (The checks are textual and syntactic: they catch mistakes, not a host
//! that deliberately hides an include, as module mode's scan.)
//!
//! **Lowered copies.** Every build writes `OUT_DIR/<name>-lowered__<path>`
//! for **every** in-place file, whether rustc compiles it or not, so a
//! lowered declaration never dangles, plus the index `<name>-lowered.txt`.
//! A passing build writes a header (the status — `NOT VERIFIED —
//! DEVELOPMENT BUILD: …` for a pending-gates build, which also says that
//! the rewrites rest on the kernel-checked links and the lifted round trip,
//! which ran; whether rustc compiles the copy; the rewritten functions; the
//! source's SHA-256) and then the lowering's text after the source's
//! leading `//!` lines: exactly the text the lifted round trip checked
//! (`driver::lowered`), or the source byte for byte when nothing was
//! cheaper. A failed build writes a `::core::compile_error!` stub instead:
//! rustc never compiles a copy of a failed build. **Fail closed**
//! ([`fail_closed`]): when the host compiles a copy, a rewrite of that file
//! rejected by the lifted round trip, a failed lowering or an optimizer
//! that did not run fails the build (a function whose replacement is not
//! cheaper keeps its verified source text, which is not a fallback).
//!
//! **Tampering and re-runs.** The copies are guarded
//! ([`BuildOutcome::guarded`]): the build script watches each
//! (`cargo::rerun-if-changed`) and the facade writes it read-only with an
//! old modification time, so the watch alone never re-runs the build
//! script, while an edit of the copy (an IDE's go-to-definition lands in
//! it) does, and the re-run rewrites it from the verified source before
//! rustc compiles it. A reused verdict needs every copy as the build wrote
//! it (the key file records the digest of the record and the copies).
//!
//! Re-runs and verdict reuse are otherwise module mode's
//! ([`super::module`]): the build script re-runs on any edit under `src/`;
//! the verdict is reused when the verdict key (toolchain, environment,
//! target, root, name and the content of every file the front end read —
//! the in-place files included) matches and the record and copies still
//! have their recorded digest.

use std::path::{Path, PathBuf};

use super::gates::{build_crate_emitting, Emission, LockUse};
use super::module::{key_text, verdict_key};
use super::{check, BuildOutcome};
use crate::loader::FileProvider;
use crate::surface::{hex, sha256};
use crate::target::TargetInfo;

/// Whether `name` is a valid record name (a lowercase identifier).
pub fn record_name_ok(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The host file that declares the module of `file` (`src/a/b.rs` or
/// `src/a/b/mod.rs` → `src/a/mod.rs`, `src/a.rs`, or the crate root), and
/// the module's name.
fn declaring_file(fs: &dyn FileProvider, src: &Path, file: &Path) -> Option<(PathBuf, String)> {
    let rel = file.strip_prefix(src).ok()?;
    let comps: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    let (name, dir): (String, Vec<String>) = if comps.last().map(String::as_str) == Some("mod.rs") {
        let n = comps.len();
        if n < 2 {
            return None;
        }
        (comps[n - 2].clone(), comps[..n - 2].to_vec())
    } else {
        let n = comps.len();
        (comps[n - 1].trim_end_matches(".rs").to_string(), comps[..n - 1].to_vec())
    };
    let base = dir.iter().fold(src.to_path_buf(), |p, c| p.join(c));
    let cands: Vec<PathBuf> = if dir.is_empty() {
        vec![src.join("lib.rs"), src.join("main.rs")]
    } else {
        let parent = dir[..dir.len() - 1].iter().fold(src.to_path_buf(), |p, c| p.join(c));
        vec![base.join("mod.rs"), parent.join(format!("{}.rs", dir[dir.len() - 1]))]
    };
    cands.into_iter().find(|c| fs.exists(c)).map(|c| (c, name))
}

/// Whether a host file declares `mod <name>;` (tokens) and has no `#[path]`.
fn declares_plain(text: &str, name: &str) -> bool {
    let stripped = super::strip_comments_ws(text);
    stripped.contains(&format!("mod{name};")) && !stripped.contains("#[path")
}

/// How the host declares an in-place module (DESIGN.md §2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Declaration {
    /// `mod m;` (no `#[path]`): rustc compiles the file as written.
    Plain,
    /// The **lowered declaration** (`crate::lift::open::lowered_include`):
    /// `mod m { //! docs  include!(concat!(env!("OUT_DIR"), "/<file>")); }`
    /// — rustc compiles the build's lowered copy `OUT_DIR/<file>`; `docs`
    /// are the declaration's inner doc strings; `ide`: it is
    /// `#[cfg(not(rust_analyzer))]` beside its IDE twin
    /// `#[cfg(rust_analyzer)] mod m;` (rust-analyzer analyzes the file
    /// itself; rustc compiles the copy).
    Lowered { file: String, docs: Vec<String>, ide: bool },
}

/// How the host file `text` declares module `m`, or why it does not
/// declare it so that rustc compiles the verified file (a `#[path]`
/// anywhere in the file, an inline module with other content, an
/// `include!` of anything but the lowered copy, no declaration).
pub fn declaration(text: &str, m: &str) -> Result<Declaration, String> {
    if super::strip_comments_ws(text).contains("#[path") {
        return Err("the file has a `#[path]` attribute".into());
    }
    if let Ok(f) = syn::parse_file(text) {
        use crate::lift::open::{ide_twin, is_ide_cfg, lowered_include};
        let decls: Vec<&syn::ItemMod> = f.items.iter().filter_map(|it| if let syn::Item::Mod(md) = it && md.ident == m { Some(md) } else { None }).collect();
        match decls.as_slice() {
            [] => {}
            [md] if md.content.is_none() => return Ok(Declaration::Plain),
            _ => {
                // the lowered declaration, alone or with its IDE twin
                let (lowered, rest): (Vec<&&syn::ItemMod>, Vec<&&syn::ItemMod>) = decls.iter().partition(|md| md.content.is_some());
                let [md] = lowered.as_slice() else { return Err(format!("`mod {m}` is declared more than once inline")) };
                let file = match lowered_include(md) {
                    Some(Ok(file)) => file,
                    Some(Err(e)) => return Err(format!("`mod {m}` includes something other than its lowered copy: {e}")),
                    None => return Err(format!("`mod {m}` is declared inline, so rustc does not compile the verified file")),
                };
                let for_ide = md.attrs.iter().any(|a| is_ide_cfg(a, true));
                match (rest.as_slice(), for_ide) {
                    ([], false) => {}
                    ([t], true) if ide_twin(t) => {}
                    ([], true) => return Err(format!("the lowered declaration of `mod {m}` is `#[cfg(not(rust_analyzer))]`: it needs its IDE twin `#[cfg(rust_analyzer)] mod {m};`")),
                    _ => return Err(format!("`mod {m}` is declared besides its lowered declaration: only the IDE twin `#[cfg(rust_analyzer)] mod {m};` may accompany it, and then the lowered declaration is `#[cfg(not(rust_analyzer))]`")),
                }
                return Ok(Declaration::Lowered { file, docs: inner_docs(&md.attrs), ide: for_ide });
            }
        }
    }
    // a declaration inside a macro (`cfg_if::cfg_if! { .. }`): textual
    if declares_plain(text, m) { Ok(Declaration::Plain) } else { Err(format!("no `mod {m};`")) }
}

/// The inner doc strings among `attrs` (`//! x` is `#![doc = " x"]`),
/// trailing whitespace trimmed.
fn inner_docs(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|a| matches!(a.style, syn::AttrStyle::Inner(_)) && a.path().is_ident("doc"))
        .filter_map(|a| match &a.meta {
            syn::Meta::NameValue(nv) => match &nv.value {
                syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value().trim_end().to_string()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The lowered copy's file name of the in-place file at `rel` (its path
/// under `src/`): `<name>-lowered__<rel, `/` as `__`>`.
pub fn copy_name(name: &str, rel: &Path) -> String {
    let flat = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("__");
    format!("{name}-lowered__{flat}")
}

/// Why the source `text` cannot be compiled from an `include!`d copy, if
/// it cannot: an inner attribute after its leading `//!` lines (an
/// `include!`d file cannot carry one), an out-of-line `mod x;` (rustc would
/// look for `x` next to the copy), or a macro whose value depends on the
/// file it is expanded in (`file!`, `line!`, `column!`, the `include`
/// macros with their relative paths).
pub fn not_includable(text: &str) -> Option<String> {
    let (_, body) = super::lifted::split_docs(text);
    if super::lifted::has_inner_attribute(body) {
        return Some("it has an inner attribute or inner doc comment after its leading `//!` lines".into());
    }
    let Ok(f) = syn::parse_file(text) else { return Some("it does not parse".into()) };
    fn out_of_line(items: &[syn::Item]) -> Option<String> {
        items.iter().find_map(|it| match it {
            syn::Item::Mod(m) => match &m.content {
                None => Some(format!("it declares the out-of-line module `mod {};`", m.ident)),
                Some((_, inner)) => out_of_line(inner),
            },
            _ => None,
        })
    }
    if let Some(why) = out_of_line(&f.items) {
        return Some(why);
    }
    fn positional(ts: proc_macro2::TokenStream) -> Option<String> {
        let toks: Vec<proc_macro2::TokenTree> = ts.into_iter().collect();
        for (i, t) in toks.iter().enumerate() {
            match t {
                proc_macro2::TokenTree::Ident(id) if matches!(id.to_string().as_str(), "file" | "line" | "column" | "include" | "include_str" | "include_bytes") => {
                    if matches!(toks.get(i + 1), Some(proc_macro2::TokenTree::Punct(p)) if p.as_char() == '!') {
                        return Some(format!("it uses `{id}!`, whose value depends on the file it is expanded in"));
                    }
                }
                proc_macro2::TokenTree::Group(g) => {
                    if let Some(w) = positional(g.stream()) {
                        return Some(w);
                    }
                }
                _ => {}
            }
        }
        None
    }
    positional(text.parse().ok()?)
}

/// An in-place file and its lowered copy (DESIGN.md §2.1): one per
/// `#[lift(in_place)]` exec module, written on every build.
#[derive(Clone, Debug)]
struct LoweredCopy {
    /// The source as the front end read it (normalized path) and its text.
    source: PathBuf,
    text: String,
    /// Its path under `src/` as the host names it (`src/merkle/mmr/iterator.rs`).
    shown: String,
    /// `OUT_DIR/<name>-lowered__<path>`.
    dst: PathBuf,
    /// The host file whose lowered declaration makes rustc compile the copy.
    used_by: Option<String>,
}

/// The SHA-256 over the record and every lowered copy (path and text): the
/// verdict key's output digest, so a reused verdict needs every copy as the
/// build wrote it.
fn outputs_digest(record: &str, copies: &[(PathBuf, String)]) -> String {
    let mut t = String::from(record);
    for (p, c) in copies {
        t.push_str(&format!("\ncopy {} {}\n", p.display(), hex(&sha256(c.as_bytes()))));
    }
    hex(&sha256(t.as_bytes()))
}

/// How a build treats the §15 gates (DESIGN.md §15).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateUse {
    /// Every gate must pass, then the lift conformance check: the record
    /// carries the verdict (`compile_lifted`).
    Enforce,
    /// **A development aid, to be removed before any landing** (DESIGN.md
    /// §2.1; §15.8 allows no opt-out): before the specification lock is
    /// accepted, every proof and law must check (the build fails
    /// otherwise), the gates run and their findings are reported but not
    /// enforced. It never yields a verdict, an accept permit or a verdict
    /// key: it writes `OUT_DIR/<name>-pending.txt` (first line
    /// [`PENDING_STATUS`]), replaces `OUT_DIR/<name>-verified.txt` with a
    /// `NOT VERIFIED` stub, marks the report's `status` and warns on every
    /// build (`compile_lifted_pending_gates`).
    Pending,
}

/// The status of a pending-gates build (record, report, warning).
pub const PENDING_STATUS: &str = "NOT VERIFIED — DEVELOPMENT BUILD: PROOFS CHECKED, §15 GATES PENDING";

/// The build logic of `sandblaster::build::compile_lifted` (module docs).
pub fn build_lifted(root: &str, name: &str, context: Option<&str>, env: &dyn Fn(&str) -> Option<String>, fs: &dyn FileProvider) -> BuildOutcome {
    build_lifted_with(root, name, context, env, fs, GateUse::Enforce)
}

/// [`build_lifted`] with the gates used as `gates` says.
pub fn build_lifted_with(root: &str, name: &str, context: Option<&str>, env: &dyn Fn(&str) -> Option<String>, fs: &dyn FileProvider, gates: GateUse) -> BuildOutcome {
    let mut o = BuildOutcome::default();
    let fail = |mut o: BuildOutcome, msg: String| {
        o.stderr.push_str(&format!("error[build]: {msg}\n"));
        o.ok = false;
        o
    };
    let Some(manifest) = env("CARGO_MANIFEST_DIR") else { return fail(o, "CARGO_MANIFEST_DIR is not set (run from a build script)".into()) };
    let Some(out_dir) = env("OUT_DIR") else { return fail(o, "OUT_DIR is not set (run from a build script)".into()) };
    let manifest = PathBuf::from(manifest);
    let out_dir = PathBuf::from(out_dir);
    if !record_name_ok(name) {
        return fail(o, format!("the record name `{name}` must be a lowercase identifier"));
    }
    for k in ["CARGO_CFG_TARGET_ARCH", "CARGO_CFG_TARGET_FEATURE", "CARGO_CFG_TARGET_ENDIAN", "CARGO_CFG_TARGET_POINTER_WIDTH"] {
        o.cargo.push(format!("cargo::rerun-if-env-changed={k}"));
    }
    let target = match TargetInfo::from_cargo_env(env) {
        Ok(t) => t,
        Err(e) => return fail(o, e),
    };
    let src = manifest.join("src");
    o.cargo.push(format!("cargo::rerun-if-changed={}", src.display()));
    // 2. the DSL root is not host source
    let root_path = manifest.join(root);
    if crate::loader::normalize(&root_path).starts_with(crate::loader::normalize(&src)) {
        return fail(o, format!("the DSL root `{root}` is under `src/`: put the laws and proofs beside `src/` (for example `sandblaster/{name}/mod.rs`)"));
    }
    if let Some(dir) = root_path.parent() {
        o.cargo.push(format!("cargo::rerun-if-changed={}", dir.display()));
    }
    let checked = check(&root_path, fs, &target);
    // only paths that exist: cargo re-runs a build script on every build
    // when a watched path is missing (the lift prelude is virtual; a lock
    // not yet accepted is absent, and its creation changes the watched
    // root directory)
    for (_, f) in checked.sm.files() {
        if fs.exists(&f.path) {
            o.cargo.push(format!("cargo::rerun-if-changed={}", f.path.display()));
        }
    }
    if fs.exists(&checked.lock_path) {
        o.cargo.push(format!("cargo::rerun-if-changed={}", checked.lock_path.display()));
    }
    let rendered = checked.render();
    if !checked.ok() {
        o.stderr.push_str(&rendered);
        o.stderr.push_str(&format!("\nerror: sandblaster: {} error(s) in `{}`\n", checked.diags.error_count(), root_path.display()));
        o.ok = false;
        return o;
    }
    if !rendered.is_empty() {
        o.stderr.push_str(&rendered);
    }
    // 3, 4. the in-place files are host source, declared so that rustc
    // compiles them as written (`mod x;`) or their lowered copy (the
    // lowered declaration)
    let nsrc = crate::loader::normalize(&src);
    let in_place: Vec<&crate::lift::LiftedInfo> = checked.lifted.iter().filter(|l| l.in_place && !l.ghost).collect();
    if in_place.is_empty() {
        return fail(o, format!("`{root}` has no `#[lift(in_place)]` module: `compile_lifted` verifies the host's own files (use `compile_module` for an emitted module)"));
    }
    let mut copies: Vec<LoweredCopy> = Vec::new();
    let mut ide_twins = false;
    for l in &in_place {
        let p = crate::loader::normalize(checked.sm.path(l.file));
        let Ok(rel) = p.strip_prefix(&nsrc) else {
            return fail(o, format!("the in-place lifted module `{}` reads `{}`, which is not under `src/`: an in-place module is the host's own file", l.name, p.display()));
        };
        let text = checked.sm.get(l.file).map(|f| f.text.clone()).unwrap_or_default();
        let shown = format!("src/{}", rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/"));
        let copy = copy_name(name, rel);
        let mut used_by = None;
        match declaring_file(fs, &nsrc, &p) {
            Some((decl, m)) => {
                let decl_shown = decl.strip_prefix(&nsrc).map(|r| format!("src/{}", r.display())).unwrap_or_else(|_| decl.display().to_string());
                let lowered_form = format!("mod {m} {{ /* the `//!` lines of `{shown}` */ include!(concat!(env!(\"OUT_DIR\"), \"/{copy}\")); }}");
                match fs.read(&decl).map(|t| declaration(&t, &m)) {
                    Ok(Ok(Declaration::Plain)) => {
                        if l.lowered_include.is_some() {
                            return fail(o, format!("internal error: the lift read a lowered declaration of `{}` that `{decl_shown}` does not have", l.name));
                        }
                    }
                    Ok(Ok(Declaration::Lowered { file, docs, ide })) => {
                        if file != copy {
                            return fail(o, format!("`{decl_shown}` includes `OUT_DIR/{file}` for `mod {m}`, but the lowered copy of `{shown}` that this build (`{name}`) writes is `OUT_DIR/{copy}`: declare `{lowered_form}`"));
                        }
                        if l.lowered_include.as_deref().is_some_and(|f| f != file) {
                            return fail(o, format!("internal error: the lift read `{}` for `{}`, the host declares `{file}`", l.lowered_include.as_deref().unwrap_or(""), l.name));
                        }
                        if let Some(why) = not_includable(&text) {
                            return fail(o, format!("`{decl_shown}` compiles `{shown}` from its lowered copy, but {why}: an `include!`d copy would not mean the same; declare `mod {m};`"));
                        }
                        let want: Vec<String> = syn::parse_file(super::lifted::split_docs(&text).0).map(|f| inner_docs(&f.attrs)).unwrap_or_default();
                        if docs != want {
                            return fail(o, format!("the lowered declaration of `mod {m}` in `{decl_shown}` must carry exactly the leading `//!` lines of `{shown}` (the module's docs, which an `include!`d file cannot carry): expected {} doc line(s), found {}; the first difference is at line {}", want.len(), docs.len(), want.iter().zip(&docs).position(|(a, b)| a != b).unwrap_or(want.len().min(docs.len())) + 1));
                        }
                        used_by = Some(decl_shown);
                        ide_twins |= ide;
                    }
                    Ok(Err(e)) => return fail(o, format!("`{decl_shown}` must declare `mod {m};` without `#[path]` (rustc compiles `{shown}`, the file verified in place) or its lowered declaration `{lowered_form}` (rustc compiles the verified lowered copy): {e}")),
                    Err(e) => return fail(o, format!("cannot read `{}`: {e}", decl.display())),
                }
            }
            None => return fail(o, format!("no host file declares the in-place module `{}` (`{}`)", l.name, p.display())),
        }
        copies.push(LoweredCopy { source: p.clone(), text, shown, dst: out_dir.join(&copy), used_by });
    }
    // every mention of this build's lowered copies under `src/` is one of
    // those declarations (a copy included elsewhere, or the copy of a file
    // that is no longer lifted, would be compiled without this build
    // writing it)
    let needle = format!("\"/{name}-lowered__");
    let files = match fs.list_rs(&src) {
        Ok(f) => f,
        Err(e) => return fail(o, format!("cannot list `{}`: {e}", src.display())),
    };
    for f in files {
        let Ok(text) = fs.read(&f) else { continue };
        let n = super::strip_comments_ws(&text).matches(&needle).count();
        let shown = f.strip_prefix(&nsrc).map(|r| format!("src/{}", r.display())).unwrap_or_else(|_| f.display().to_string());
        let expected = copies.iter().filter(|c| c.used_by.as_deref() == Some(shown.as_str())).count();
        if n != expected {
            return fail(o, format!("`{shown}` mentions a lowered copy of `{name}` (`OUT_DIR/{name}-lowered__..`) that is not the lowered declaration of an in-place module of `{root}`: only the host file that declares an in-place module may include its copy, once"));
        }
    }
    for c in &copies {
        o.cargo.push(format!("cargo::rerun-if-changed={}", c.dst.display()));
        o.guarded.push(c.dst.clone());
    }
    // the IDE twin's cfg is known to rustc's cfg check (rust-analyzer sets
    // it; a build that sets it compiles the in-place files as written)
    o.cargo.push("cargo::rustc-check-cfg=cfg(rust_analyzer)".into());
    if env("CARGO_CFG_RUST_ANALYZER").is_some() && ide_twins {
        o.cargo.push("cargo::warning=sandblaster: `cfg(rust_analyzer)` is set: rustc compiles the IDE twins (the in-place files as written, verified but not optimized), not the lowered copies".into());
    }
    o.cargo.push("cargo::rerun-if-env-changed=SANDBLASTER_STRICT_OPT".into());
    o.cargo.push("cargo::rerun-if-env-changed=SANDBLASTER_MEM_LIMIT_GB".into());
    o.cargo.push("cargo::rerun-if-env-changed=RUSTC".into());
    let out = format!("{name}-verified.txt");
    let code_path = out_dir.join(&out);
    let key_path = out_dir.join(format!("{name}-verdict.key"));
    // (a pending-gates build never reuses a verdict: it has none)
    let conform = crate::conform::Config::for_build(env, fs, &manifest, &out_dir, name, context);
    let key = if gates == GateUse::Enforce { context.map(|ctx| verdict_key(ctx, env, fs, &root_path, &format!("in-place\nout {name}\nedition {}", conform.edition), &checked)) } else { None };
    if let Some(k) = &key
        && let (Ok(kt), Ok(code)) = (fs.read(&key_path), fs.read(&code_path))
        && let Some(on_disk) = copies.iter().map(|c| fs.read(&c.dst).ok().map(|t| (c.dst.clone(), t))).collect::<Option<Vec<_>>>()
        && kt == key_text(k, &outputs_digest(&code, &on_disk))
    {
        o.cargo.push(format!("cargo::warning=sandblaster: `{name}` verified in place, unchanged (verdict key {}): reusing `{}` and its lowered copies", &k[..16], code_path.display()));
        o.ok = true;
        return o;
    }
    let root_display = root_path.display().to_string();
    let b = build_crate_emitting(&checked, LockUse::Enforce, &root_display, &Emission::InPlace { out: out.clone(), conform });
    if gates == GateUse::Pending {
        let mut o = pending_outcome(o, &b, &checked, name, root, &root_display, &out_dir, &code_path, &key_path);
        let mut closed = None;
        if o.ok
            && let Err(e) = fail_closed(&b, &copies)
        {
            o.stderr.push_str(&format!("error[build]: {e}\n"));
            o.ok = false;
            closed = Some(e);
        }
        let (files, index) = lowered_copies(&b, &copies, &out_dir, name, &root_display, PENDING_STATUS, o.ok);
        if let Some((_, record)) = o.outputs.iter_mut().find(|(p, _)| p.ends_with(format!("{name}-pending.txt"))) {
            if let Some(e) = &closed {
                record.push_str(&format!("\nBUILD FAILED: {e}\n"));
            }
            record.push_str(&format!("\nlowered copies (OUT_DIR/{name}-lowered.txt):\n{index}"));
        }
        o.outputs.extend(files);
        return o;
    }
    let verdict_status = match &b.verdict {
        Some(_) if b.lowered_in_place.iter().any(|l| l.lowered() > 0) => "VERIFIED + LIFTED IN PLACE + OPTIMIZED",
        Some(_) => "VERIFIED + LIFTED IN PLACE",
        None => "NOT VERIFIED (the build issued no verdict)",
    };
    let mut ok = b.verdict.is_some();
    if ok && let Err(e) = fail_closed(&b, &copies) {
        o.stderr.push_str(&format!("error[build]: {e}\n"));
        ok = false;
    }
    let (files, index) = lowered_copies(&b, &copies, &out_dir, name, &root_display, verdict_status, ok);
    o.outputs.push((out_dir.join(format!("{name}-report.json")), b.report.clone()));
    o.outputs.push((out_dir.join(format!("{name}-timing.json")), b.timing.clone()));
    let verdict = match &b.verdict {
        Some(v) if ok => v,
        _ => {
            if b.verdict.is_none() {
                o.stderr.push_str(&b.render_failure(&checked, &root_display));
            }
            o.outputs.extend(files);
            o.outputs.push((key_path, String::new()));
            o.ok = false;
            return o;
        }
    };
    let record = format!("{}// Lowered copies (`OUT_DIR/{name}-lowered.txt`):\n{}", verdict.code(), index.lines().map(|l| format!("//   {l}\n")).collect::<String>());
    let written: Vec<(PathBuf, String)> = files.iter().filter(|(p, _)| copies.iter().any(|c| &c.dst == p)).cloned().collect();
    let digest = outputs_digest(&record, &written);
    o.outputs.insert(0, (code_path, record));
    o.outputs.extend(files);
    if let Some(k) = &key {
        o.outputs.push((key_path, key_text(k, &digest)));
    }
    o.cargo.push(format!("cargo::warning=sandblaster: `{name}` verified in place (`{root}`): {}", verdict.summary()));
    o.ok = true;
    o
}

/// Fail closed (DESIGN.md §2.1): a host file compiled from its lowered copy
/// needs this build's lowering of it, with nothing rejected by the lifted
/// round trip — no silent fallback. (A function whose replacement is not
/// cheaper keeps its source text: that is the verified source, not a
/// fallback.)
fn fail_closed(b: &super::gates::CrateBuild, copies: &[LoweredCopy]) -> Result<(), String> {
    for c in copies.iter().filter(|c| c.used_by.is_some()) {
        let decl = c.used_by.as_deref().unwrap_or_default();
        let Some(l) = b.lowered_in_place.iter().find(|l| Path::new(&l.file) == c.source) else {
            let why = if b.lifted_opt_warnings.is_empty() { "the optimizer did not run".to_string() } else { b.lifted_opt_warnings.join("; ") };
            return Err(format!("`{decl}` compiles `{}` from its lowered copy, but this build did not lower it ({why})", c.shown));
        };
        if let Some(n) = &l.note {
            return Err(format!("`{decl}` compiles `{}` from its lowered copy, but its lowering failed: {n}", c.shown));
        }
        for r in &l.records {
            if let super::lowered::LowerOutcome::Kept(why) = &r.outcome
                && why.starts_with(super::lowered::ROUND_TRIP_REJECTED)
            {
                return Err(format!("`{decl}` compiles `{}` from its lowered copy, but the lifted round trip rejected the rewrite of `{}`: {why}", c.shown, r.function));
            }
        }
    }
    Ok(())
}

/// The lowered copy of every in-place file (`OUT_DIR/<name>-lowered__<path
/// under src/, `/` as `__`>`, DESIGN.md §2.1), written on every build so a
/// lowered declaration never dangles, and the index `<name>-lowered.txt`.
/// When the build passed (`ok`), a copy is a header (the build's `status`,
/// whether rustc compiles it, what was rewritten) and then the lowering's
/// text after the source's leading `//!` lines — the source with the
/// rewritten functions' bodies calling their replacements, appended, exactly
/// as the lifted round trip checked it — or the source as-is when nothing
/// was cheaper. When the build failed, every copy is a `compile_error!`
/// stub: rustc never compiles a copy of a failed build.
fn lowered_copies(b: &super::gates::CrateBuild, copies: &[LoweredCopy], out_dir: &Path, name: &str, root_display: &str, status: &str, ok: bool) -> (Vec<(PathBuf, String)>, String) {
    let mut files = Vec::new();
    let mut index = format!("{status}\nsandblaster lowered copies of `{name}` ({root_display}): the host's in-place files with functions rewritten to their optimizer replacements (kernel-checked links, lifted round trip); one per file, on every build\n");
    let pending = status == PENDING_STATUS;
    for c in copies {
        let shown_dst = c.dst.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        let src_sha = hex(&sha256(c.text.as_bytes()));
        let compiled = match &c.used_by {
            Some(d) => format!("COMPILED: rustc compiles this file as the module declared in `{d}`, in place of `{}`.", c.shown),
            None => format!("NOT COMPILED: the host compiles `{}` as written (declare the module with its lowered declaration to compile this copy).", c.shown),
        };
        if !ok {
            let text = format!(
                "// @generated by sandblaster from `{root_display}`. Do not edit.\n// The build of `{name}` failed: there is no verified lowered copy of `{}` (see the build script's output).\n::core::compile_error!(\"sandblaster: the build of `{name}` failed, so this build has no verified lowered copy of `{}`\");\n",
                c.shown, c.shown
            );
            index.push_str(&format!("{shown_dst}: FAILED BUILD (a `compile_error!` stub)\n"));
            files.push((c.dst.clone(), text));
            continue;
        }
        let low = b.lowered_in_place.iter().find(|l| Path::new(&l.file) == c.source);
        let (_, src_body) = super::lifted::split_docs(&c.text);
        let rewritten: Vec<String> = low
            .map(|l| {
                l.records
                    .iter()
                    .filter_map(|r| match &r.outcome {
                        super::lowered::LowerOutcome::Lowered { rung, cost_source, cost_residual, via, .. } => {
                            let via = if via.is_empty() { String::new() } else { format!("; {via}") };
                            Some(format!("rewritten: `{}` (rung {rung}; portable cost {cost_source} -> {cost_residual} milli-cycles{via})", r.function))
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let body: &str = match low {
            Some(l) if !rewritten.is_empty() => &l.body,
            _ => src_body,
        };
        let mut head = format!("// @generated by sandblaster from `{root_display}`. Do not edit: edit `{}`, the verified source (the build rewrites this file).\n// STATUS: {status}\n", c.shown);
        if pending {
            head.push_str("//   The §15 gates (the specification lock) are pending: this build issues no verdict that the laws pin the\n//   behaviour down. The rewrites below do not depend on them: each rests on a kernel-checked link to the source\n//   function and on the lifted round trip, which ran in this build (DESIGN.md §2.1).\n");
        }
        head.push_str(&format!("// {compiled}\n"));
        if rewritten.is_empty() {
            head.push_str(&format!("// The code below is `{}` byte for byte after its leading `//!` lines (the declaration carries them): nothing was cheaper.\n", c.shown));
        } else {
            head.push_str(&format!(
                "// The code below is `{}` after its leading `//!` lines (the declaration carries them), except the bodies of the\n// functions listed here: each calls its replacement, appended at the end, kernel-checked equal to the function and\n// read back by the lift (the lifted round trip, DESIGN.md §2.1).\n",
                c.shown
            ));
            for r in &rewritten {
                head.push_str(&format!("//   {r}\n"));
            }
        }
        head.push_str(&format!("// source `{}` sha256 {src_sha}\n", c.shown));
        let text = format!("{head}{body}");
        index.push_str(&format!("{shown_dst} sha256 {} ({}; source `{}` sha256 {src_sha})\n", hex(&sha256(text.as_bytes())), if c.used_by.is_some() { "compiled by rustc" } else { "not compiled" }, c.shown));
        for r in &rewritten {
            index.push_str(&format!("  {r}\n"));
        }
        files.push((c.dst.clone(), text));
    }
    files.push((out_dir.join(format!("{name}-lowered.txt")), index.clone()));
    // the lifted round trip's copy of each file read from rustc's MIR that
    // had rewrites (whether or not its round trip passed): the text whose
    // MIR the round trip reads (`extract.sh --replace`, docs/mir-lift.md §20.1)
    for l in &b.lowered_in_place {
        if let Some((flat, text)) = &l.roundtrip_copy {
            files.push((out_dir.join(format!("{name}-roundtrip__{flat}.rs")), text.clone()));
        }
    }
    (files, index)
}

/// The outcome of a pending-gates build ([`GateUse::Pending`]): a failed
/// proof or law (or a front-end/emission-chain error) fails the build;
/// otherwise the record `OUT_DIR/<name>-pending.txt` lists what was checked
/// and the gate findings. Never a verdict: even when every gate and the lift
/// conformance check passed, the record is the pending one (switch to
/// `compile_lifted` for the verdict), and `OUT_DIR/<name>-verified.txt` and
/// the verdict key are overwritten so no earlier verdict survives.
#[allow(clippy::too_many_arguments)]
fn pending_outcome(mut o: BuildOutcome, b: &super::gates::CrateBuild, checked: &super::Checked, name: &str, root: &str, root_display: &str, out_dir: &Path, code_path: &Path, key_path: &Path) -> BuildOutcome {
    let report = b.report.replacen(&format!("\"status\": \"{}\"", b.status()), &format!("\"status\": \"{PENDING_STATUS}\""), 1);
    let report = super::gates::splice_json_field(&report, "development_build", "\"compile_lifted_pending_gates: the §15 gates are reported, not enforced; this build carries no verdict (DESIGN.md §2.1)\"");
    o.outputs.push((out_dir.join(format!("{name}-report.json")), report));
    o.outputs.push((out_dir.join(format!("{name}-timing.json")), b.timing.clone()));
    // no verified record and no verdict key of an earlier build survives
    o.outputs.push((code_path.to_path_buf(), format!("NOT VERIFIED: `{name}` was last built by `compile_lifted_pending_gates`, a development aid that issues no verdict (see `{name}-pending.txt` when that build passed its proofs); this file is not a verified record\n")));
    o.outputs.push((key_path.to_path_buf(), String::new()));
    let chain_failed = !b.gates.chain.is_empty() || b.emit_error.is_some();
    if !b.v.proofs_ok || chain_failed {
        o.stderr.push_str(&b.render_failure(checked, root_display));
        o.stderr.push_str(&format!("\nerror: sandblaster: `{name}` (`{root}`): {}; a pending-gates build still requires every proof and law\n", if chain_failed { "the emission chain failed" } else { "a proof or law did not check" }));
        o.ok = false;
        return o;
    }
    let st = b.v.stats();
    let findings: Vec<(&str, usize)> = b.gates.results.iter().filter(|r| r.errors > 0 && r.gate != "lift-conformance").map(|r| (r.gate, r.errors)).collect();
    let total: usize = findings.iter().map(|(_, n)| n).sum();
    let listed: Vec<String> = findings.iter().map(|(g, n)| format!("{g}: {n}")).collect();
    let conformance = match &b.gates.conformance {
        None => "not run (it runs after every §15 gate passed)".to_string(),
        Some(r) if r.passed() => format!("passed: {}", r.summary()),
        Some(r) => format!("FAILED: {}", r.failures().join("; ")),
    };
    let mut record = format!(
        "{PENDING_STATUS}\nsandblaster in-place record `{name}` ({root}), written by `compile_lifted_pending_gates` (a development aid, removed before landing: DESIGN.md §2.1)\n{} of {} obligation(s) proven; every definition and law kernel-checked\n§15 gate findings (reported, not enforced): {total} ({})\nlift conformance: {conformance}\nno verdict: this record does not state that the module meets its specification lock or that the lift read the source correctly\n\n",
        st.total - st.failed - st.todo,
        st.total,
        if listed.is_empty() { "none".to_string() } else { listed.join(", ") }
    );
    record.push_str(&b.gates.diags.render(&checked.sm));
    o.stderr.push_str(&b.gates.diags.render(&checked.sm));
    if let Some(r) = b.gates.conformance.as_ref().filter(|r| !r.passed()) {
        for f in r.failures() {
            o.stderr.push_str(&format!("warning[lift-conformance]: {f}\n"));
        }
    }
    o.outputs.insert(0, (out_dir.join(format!("{name}-pending.txt")), record));
    let switch = if total == 0 && b.gates.conformance.as_ref().is_some_and(|r| r.passed()) { "; every gate and the lift conformance check passed: switch to `compile_lifted` for the verdict" } else { "" };
    o.cargo.push(format!("cargo::warning=sandblaster: `{name}` ({root}): {PENDING_STATUS} ({} obligations proven; {total} §15 gate finding(s), not enforced; lift conformance {}){switch}", st.total, if b.gates.conformance.is_none() { "not run" } else if b.gates.conformance.as_ref().is_some_and(|r| r.passed()) { "passed" } else { "FAILED" }));
    o.ok = true;
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations_and_names() {
        assert!(record_name_ok("mmr") && record_name_ok("mmr_2"));
        // negative twins: not identifiers
        assert!(!record_name_ok("Mmr") && !record_name_ok("2mmr") && !record_name_ok("") && !record_name_ok("a-b"));
        assert!(declares_plain("pub mod mmr;\nmod position;\n", "position"));
        assert!(declares_plain("// c\npub(crate) mod  position ;", "position"));
        // negative twins: a `#[path]`, or no declaration
        assert!(!declares_plain("#[path = \"x.rs\"]\nmod position;\n", "position"));
        assert!(!declares_plain("mod positions;\n", "position"));
    }

    #[test]
    fn the_lowered_declaration_and_its_twins() {
        let inc = "include!(concat!(env!(\"OUT_DIR\"), \"/mmr-lowered__merkle__mmr__iterator.rs\"));";
        let ok = format!("//! Parent.\npub mod batch;\npub mod iterator {{\n    //! Docs.\n    //!\n    {inc}\n}}\n");
        assert_eq!(declaration(&ok, "iterator"), Ok(Declaration::Lowered { file: "mmr-lowered__merkle__mmr__iterator.rs".into(), docs: vec![" Docs.".to_string(), String::new()], ide: false }));
        // with its IDE twin (either order)
        let twin = format!("#[cfg(rust_analyzer)]\npub mod iterator;\n#[cfg(not(rust_analyzer))]\npub mod iterator {{\n    //! Docs.\n    {inc}\n}}\n");
        assert!(matches!(declaration(&twin, "iterator"), Ok(Declaration::Lowered { ide: true, .. })));
        let twin2 = format!("#[cfg(not(rust_analyzer))]\npub mod iterator {{\n    {inc}\n}}\n/// Docs.\n#[cfg(rust_analyzer)]\npub mod iterator;\n");
        assert!(matches!(declaration(&twin2, "iterator"), Ok(Declaration::Lowered { ide: true, .. })));
        // negative twins of the IDE twin: one without the other, a twin
        // with another cfg, an inline twin, a plain second declaration
        for bad in [
            format!("#[cfg(not(rust_analyzer))]\nmod iterator {{ {inc} }}\n"),
            format!("#[cfg(rust_analyzer)]\nmod iterator;\nmod iterator {{ {inc} }}\n"),
            format!("#[cfg(feature = \"x\")]\nmod iterator;\n#[cfg(not(rust_analyzer))]\nmod iterator {{ {inc} }}\n"),
            format!("#[cfg(rust_analyzer)]\nmod iterator {{ include!(\"iterator.rs\"); }}\n#[cfg(not(rust_analyzer))]\nmod iterator {{ {inc} }}\n"),
            format!("mod iterator;\n#[cfg(not(rust_analyzer))]\nmod iterator {{ {inc} }}\n"),
            format!("#[cfg(not(rust_analyzer))]\n#[cfg(not(rust_analyzer))]\nmod iterator {{ {inc} }}\n#[cfg(rust_analyzer)]\nmod iterator;\n"),
        ] {
            assert!(declaration(&bad, "iterator").is_err(), "{bad}");
        }
        assert_eq!(declaration(&ok, "batch"), Ok(Declaration::Plain));
        // whitespace and comments do not matter
        let spaced = "mod iterator { // c\n include ! ( concat ! ( env ! ( \"OUT_DIR\" ) , \"/mmr-lowered__merkle__mmr__iterator.rs\" ) ) ; }\n";
        assert!(matches!(declaration(spaced, "iterator"), Ok(Declaration::Lowered { .. })));
        // negative twins: an arbitrary file, another macro path or shape,
        // another argument, an extra item or attribute, a `#[path]`, an
        // inline body, no declaration
        for bad in [
            "mod iterator { include!(\"iterator_fast.rs\"); }",
            "mod iterator { include!(concat!(env!(\"OUT_DIR\"), \"/iterator.rs\")); }",
            "mod iterator { include!(concat!(env!(\"OUT_DIR\"), \"/Mmr-lowered__x.rs\")); }",
            "mod iterator { include!(concat!(env!(\"OUT_DIR\"), \"/mmr-lowered__../x.rs\")); }",
            "mod iterator { include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/mmr-lowered__x.rs\")); }",
            "mod iterator { ::core::include!(concat!(env!(\"OUT_DIR\"), \"/mmr-lowered__x.rs\")); }",
            "mod iterator { include_str!(concat!(env!(\"OUT_DIR\"), \"/mmr-lowered__x.rs\")); }",
            "mod iterator { include!(concat!(env!(\"OUT_DIR\"), \"/mmr-lowered__x.rs\")); fn f() {} }",
            "#[cfg(any())]\nmod iterator { include!(concat!(env!(\"OUT_DIR\"), \"/mmr-lowered__x.rs\")); }",
            "mod iterator { #[allow(unused)] include!(concat!(env!(\"OUT_DIR\"), \"/mmr-lowered__x.rs\")); }",
            "#[path = \"x.rs\"]\nmod iterator;",
            "mod iterator { pub fn f() {} }",
            "mod other;",
        ] {
            assert!(declaration(bad, "iterator").is_err(), "{bad}");
        }
        // an ordinary inline module is not an include
        assert!(crate::lift::open::lowered_include(&syn::parse_str::<syn::ItemMod>("mod m { fn f() {} }").unwrap()).is_none());
    }

    #[test]
    fn copies_are_named_and_sources_screened() {
        assert_eq!(copy_name("mmr", Path::new("merkle/mmr/iterator.rs")), "mmr-lowered__merkle__mmr__iterator.rs");
        assert_eq!(not_includable("//! Docs.\nfn f() -> u8 { 1 }\n#[cfg(test)]\nmod tests { fn g() {} }\n"), None);
        // negative twins
        assert!(not_includable("//! Docs.\n#![allow(dead_code)]\nfn f() {}\n").unwrap().contains("inner attribute"));
        assert!(not_includable("fn f() {}\nmod inner { mod deep; }\n").unwrap().contains("`mod deep;`"));
        for m in ["file", "line", "column", "include", "include_str", "include_bytes"] {
            let t = format!("fn f() {{ let _ = {{ {m}!(\"x\") }}; }}\n");
            assert!(not_includable(&t).unwrap().contains(&format!("`{m}!`")), "{m}");
        }
        assert_eq!(not_includable("fn line() -> u32 { 0 }\nfn f() -> u32 { line() }\n"), None);
    }

    #[test]
    fn the_output_digest_covers_every_copy() {
        let a = vec![(PathBuf::from("o/m-lowered__a.rs"), "fn a() {}\n".to_string())];
        let d = outputs_digest("record", &a);
        assert_eq!(d, outputs_digest("record", &a));
        // negative twins: a tampered copy, a missing copy, another record
        let tampered = vec![(PathBuf::from("o/m-lowered__a.rs"), "fn a() { evil() }\n".to_string())];
        assert_ne!(d, outputs_digest("record", &tampered));
        assert_ne!(d, outputs_digest("record", &[]));
        assert_ne!(d, outputs_digest("record2", &a));
    }
}
