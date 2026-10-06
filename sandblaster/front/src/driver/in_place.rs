//! In-place lifted modules (DESIGN.md §2.1 "in place", SEMANTICS.md §19.5):
//! `sandblaster::build::compile_lifted(root, name)` verifies a DSL root whose
//! lifted exec modules are the host crate's own files
//! (`#[lift(in_place)] #[path = "../../src/x.rs"] mod x;`). rustc compiles
//! those files as written: what was verified is what ships. The build
//! writes the record `OUT_DIR/<name>-verified.txt` (which files, their
//! hashes, the instances, what stays unchecked host code, the host
//! obligations), `OUT_DIR/<name>-report.json` and `-timing.json`.
//!
//! Checks before verification:
//!
//! 1. `name` is a lowercase identifier;
//! 2. the DSL root is not under `src/` (its laws and proofs are not host code);
//! 3. every in-place lifted file is under `src/` — it must be host source;
//! 4. the host file that declares each in-place module declares it as
//!    `mod <m>;` with no `#[path]` attribute in the file ([`declaration`]),
//!    so rustc compiles the verified file itself.
//!
//! (The checks are textual and syntactic: they catch mistakes, not a host
//! that deliberately hides an include, as module mode's scan.)
//!
//! **Re-runs and verdict reuse** are module mode's ([`super::module`]): the
//! build script re-runs on any edit under `src/` (and of the inputs below
//! outside the host crate); the verdict is reused when the **verdict key**
//! matches and the record still has its recorded digest. The key is module mode's — the verifier context
//! (toolchain identity, overflow checks, `rustc -vV`, the `SANDBLASTER_*`
//! variables that can change a result), the target, the root, the name,
//! the edition and the content of every file the front end read (the DSL
//! files — laws, proofs, words —, the in-place files, the `.sbmir` files)
//! and the lock — plus the **host inputs** of the lift
//! conformance check (`conform::host_inputs`: every file under `src/`, the
//! copy's manifest, the workspace manifest and lock, the features, the
//! files of every path dependency, cargo, its configuration and the
//! environment that changes its build), because the conformance check
//! compiles all of them.
//!
//! **The shared verdict cache** ([`super::cache`]): when `OUT_DIR` has no
//! matching key file (a new target directory, another profile, `cargo
//! clean`), the whole verdict — every output this build writes to
//! `OUT_DIR` — is looked up under the same key (namespace [`CACHE_NS`];
//! integrity-checked: a tampered entry is rejected and the crate verified),
//! and a new verdict is stored there. On a miss, the build reuses what did
//! not change, each under its own key: the theorem gate's verdicts (replayed through the kernel), and the lift
//! conformance check's pass (`conform`: its key covers its inputs only, so
//! an edit of a law or a proof, or of the lock, does not re-run it).

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

/// How the host file `text` declares module `m`: `Ok` for `mod m;` (no
/// `#[path]` anywhere in the file), so that rustc compiles the verified
/// file; otherwise why not (a `#[path]` in the file, an inline module, a
/// second declaration, no declaration).
pub fn declaration(text: &str, m: &str) -> Result<(), String> {
    if super::strip_comments_ws(text).contains("#[path") {
        return Err("the file has a `#[path]` attribute".into());
    }
    if let Ok(f) = syn::parse_file(text) {
        let decls: Vec<&syn::ItemMod> = f.items.iter().filter_map(|it| if let syn::Item::Mod(md) = it && md.ident == m { Some(md) } else { None }).collect();
        match decls.as_slice() {
            [] => {}
            [md] if md.content.is_none() => return Ok(()),
            [_] => return Err(format!("`mod {m}` is declared inline, so rustc does not compile the verified file")),
            _ => return Err(format!("`mod {m}` is declared more than once")),
        }
    }
    // a declaration inside a macro (`cfg_if::cfg_if! { .. }`): textual
    if declares_plain(text, m) { Ok(()) } else { Err(format!("no `mod {m};`")) }
}

/// The SHA-256 of the record: the verdict key's output digest, so a reused
/// verdict needs the record as the build wrote it.
fn outputs_digest(record: &str) -> String {
    hex(&sha256(record.as_bytes()))
}

/// The build logic of `sandblaster::build::compile_lifted` (module docs).
/// Every proof, law and §15 gate must pass, then the lift conformance
/// check: the record carries the verdict (there is no opt-out, §15.8).
pub fn build_lifted(root: &str, name: &str, context: Option<&str>, env: &dyn Fn(&str) -> Option<String>, fs: &dyn FileProvider) -> BuildOutcome {
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
    let mut checked = check(&root_path, fs, &target);
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
    // compiles them as written (`mod x;`)
    let nsrc = crate::loader::normalize(&src);
    let in_place: Vec<&crate::lift::LiftedInfo> = checked.lifted.iter().filter(|l| l.in_place && !l.ghost).collect();
    if in_place.is_empty() {
        return fail(o, format!("`{root}` has no `#[lift(in_place)]` module: `compile_lifted` verifies the host's own files (use `compile_module` for an emitted module)"));
    }
    for l in &in_place {
        let p = crate::loader::normalize(checked.sm.path(l.file));
        let Ok(rel) = p.strip_prefix(&nsrc) else {
            return fail(o, format!("the in-place lifted module `{}` reads `{}`, which is not under `src/`: an in-place module is the host's own file", l.name, p.display()));
        };
        let shown = format!("src/{}", rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/"));
        match declaring_file(fs, &nsrc, &p) {
            Some((decl, m)) => {
                let decl_shown = decl.strip_prefix(&nsrc).map(|r| format!("src/{}", r.display())).unwrap_or_else(|_| decl.display().to_string());
                match fs.read(&decl).map(|t| declaration(&t, &m)) {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return fail(o, format!("`{decl_shown}` must declare `mod {m};` without `#[path]` (rustc compiles `{shown}`, the file verified in place): {e}")),
                    Err(e) => return fail(o, format!("cannot read `{}`: {e}", decl.display())),
                }
            }
            None => return fail(o, format!("no host file declares the in-place module `{}` (`{}`)", l.name, p.display())),
        }
    }
    o.cargo.push("cargo::rerun-if-env-changed=SANDBLASTER_MEM_LIMIT_GB".into());
    o.cargo.push("cargo::rerun-if-env-changed=RUSTC".into());
    let out = format!("{name}-verified.txt");
    let code_path = out_dir.join(&out);
    let key_path = out_dir.join(format!("{name}-verdict.key"));
    // the verdict key (module docs): module mode's — every file the front
    // end read, the lock, the target, the context — plus the
    // host inputs of the lift conformance check (everything its copy of the
    // host crate compiles or is configured by)
    let conform = crate::conform::Config::for_build(env, fs, &manifest, &out_dir, name, context);
    let key = match context {
        Some(ctx) => match crate::conform::host_inputs(&conform) {
            Ok(h) => {
                for w in &h.watch {
                    o.cargo.push(format!("cargo::rerun-if-changed={}", w.display()));
                }
                Some(verdict_key(ctx, env, &root_path, &format!("in-place\nout {name}\nedition {}\nhost-inputs {}", conform.edition, hex(&sha256(h.text.as_bytes()))), &checked))
            }
            Err(e) => {
                o.cargo.push(format!("cargo::warning=sandblaster: `{name}`: no verdict reuse (the host inputs of the lift conformance check: {})", e.replace('\n', " ")));
                None
            }
        },
        None => None,
    };
    if let Some(k) = &key
        && let (Ok(kt), Ok(code)) = (fs.read(&key_path), fs.read(&code_path))
        && kt == key_text(k, &outputs_digest(&code))
    {
        o.cargo.push(format!("cargo::warning=sandblaster: `{name}` verified in place, unchanged (verdict key {}): reusing `{}`", &k[..16], code_path.display()));
        o.ok = true;
        return o;
    }
    // the shared verdict cache (module docs): the whole verdict, else (on a
    // miss) the theorem gate's replays and the conformance passes whose inputs did
    // not change
    let cache = super::module::open_cache(context, env, &mut o);
    if let (Some(k), Some(vc)) = (&key, &cache)
        && let Some(digest) = reuse_cached(vc, k, name, &out_dir, &mut o)
    {
        o.outputs.push((key_path, key_text(k, &digest)));
        o.cargo.push(format!("cargo::warning=sandblaster: `{name}` verified in place, unchanged (verdict key {}): reusing the verdict cache entry in `{}`", &k[..16], vc.store.dir().display()));
        o.ok = true;
        return o;
    }
    if let Some(vc) = &cache {
        checked.cache = Some(std::sync::Arc::new(vc.clone()));
    }
    let root_display = root_path.display().to_string();
    let b = build_crate_emitting(&checked, LockUse::Enforce, &root_display, &Emission::InPlace { out: out.clone(), conform });
    o.outputs.push((out_dir.join(format!("{name}-report.json")), b.report.clone()));
    o.outputs.push((out_dir.join(format!("{name}-timing.json")), b.timing.clone()));
    let Some(verdict) = &b.verdict else {
        o.stderr.push_str(&b.render_failure(&checked, &root_display));
        o.outputs.push((key_path, String::new()));
        o.ok = false;
        return o;
    };
    let record = verdict.code().to_string();
    let digest = outputs_digest(&record);
    o.outputs.insert(0, (code_path, record));
    if let Some(k) = &key {
        if let Some(vc) = &cache {
            store_cached(vc, k, &out_dir, &o.outputs, &mut o.cargo);
        }
        o.outputs.push((key_path, key_text(k, &digest)));
    }
    o.cargo.push(format!("cargo::warning=sandblaster: `{name}` verified in place (`{root}`): {}", verdict.summary()));
    o.ok = true;
    o
}

/// The namespace of whole in-place verdicts in the shared verdict cache
/// (`driver::cache`).
pub const CACHE_NS: &str = "in-place";

/// Stores a whole in-place verdict under `key`: every output of the build
/// in `OUT_DIR` (the record, the report, the timing), by file name (a
/// failure is a warning).
fn store_cached(vc: &super::cache::VerdictCache, key: &str, out_dir: &Path, outputs: &[(PathBuf, String)], cargo: &mut Vec<String>) {
    let files: Vec<(&str, &str)> = outputs.iter().filter(|(p, _)| p.parent() == Some(out_dir)).filter_map(|(p, t)| p.file_name().and_then(|f| f.to_str()).map(|f| (f, t.as_str()))).collect();
    if let Err(e) = vc.store.put(CACHE_NS, key, &files) {
        cargo.push(format!("cargo::warning=sandblaster: verdict cache: {}", e.replace('\n', " ")));
    }
}

/// A whole in-place verdict of the shared cache under `key`: pushes every
/// stored output (into `OUT_DIR`) and returns the output digest of the
/// record (the key file's); `None` on a miss, or on an entry without the
/// record (a warning: the crate is verified).
fn reuse_cached(vc: &super::cache::VerdictCache, key: &str, name: &str, out_dir: &Path, o: &mut BuildOutcome) -> Option<String> {
    let files = match vc.store.get(CACHE_NS, key) {
        super::cache::Lookup::Hit(files) => files,
        super::cache::Lookup::Miss => return None,
        super::cache::Lookup::Rejected(why) => {
            o.cargo.push(format!("cargo::warning=sandblaster: verdict cache entry {}… rejected ({why}); verifying", &key[..16]));
            return None;
        }
    };
    let get = |n: &str| files.iter().find(|(f, _)| f == n).map(|(_, t)| t.clone());
    let Some(record) = get(&format!("{name}-verified.txt")) else {
        o.cargo.push(format!("cargo::warning=sandblaster: verdict cache entry {}… rejected (it lacks the record); verifying", &key[..16]));
        return None;
    };
    for (f, t) in files {
        o.outputs.push((out_dir.join(f), t));
    }
    Some(outputs_digest(&record))
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
    fn only_a_plain_declaration_is_accepted() {
        let ok = "//! Parent.\npub mod batch;\npub mod iterator;\n";
        assert_eq!(declaration(ok, "iterator"), Ok(()));
        assert_eq!(declaration(ok, "batch"), Ok(()));
        // inside a macro: textual
        assert_eq!(declaration("cfg_if::cfg_if! { if #[cfg(x)] { pub mod iterator; } }\n", "iterator"), Ok(()));
        // negative twins: an inline module (an `include!` of anything, the
        // former lowered declaration), a second declaration, a `#[path]`,
        // no declaration
        let inc = "include!(concat!(env!(\"OUT_DIR\"), \"/mmr-lowered__merkle__mmr__iterator.rs\"));";
        for bad in [
            format!("pub mod iterator {{\n    //! Docs.\n    {inc}\n}}\n"),
            format!("#[cfg(rust_analyzer)]\npub mod iterator;\n#[cfg(not(rust_analyzer))]\npub mod iterator {{ {inc} }}\n"),
            "#[cfg(a)]\nmod iterator;\n#[cfg(not(a))]\nmod iterator;\n".to_string(),
            "mod iterator { pub fn f() {} }\n".to_string(),
            "#[path = \"x.rs\"]\nmod iterator;\n".to_string(),
            "mod other;\n".to_string(),
        ] {
            assert!(declaration(&bad, "iterator").is_err(), "{bad}");
        }
    }

    #[test]
    fn the_output_digest_covers_the_record() {
        let d = outputs_digest("record");
        assert_eq!(d, outputs_digest("record"));
        // negative twin: another record
        assert_ne!(d, outputs_digest("record2"));
    }
}
