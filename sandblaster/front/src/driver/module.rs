//! Module mode (DESIGN.md §2.1): a verified module inside an ordinary crate.
//!
//! ```text
//! host/
//!   Cargo.toml            [build-dependencies] sandblaster = { features = ["build"] }
//!   build.rs              sandblaster::build::compile_module("sandblaster/varint/mod.rs", "src/verified/varint.rs");
//!   src/lib.rs            ordinary host code: `mod verified;` ...
//!   src/verified/mod.rs   `pub mod varint;` (ordinary host code)
//!   src/verified/varint.rs include!(concat!(env!("OUT_DIR"), "/varint.rs"));   (nothing else)
//!   sandblaster/varint/     the DSL root, its laws, proofs and SPEC.lock
//! ```
//!
//! [`build_module`] verifies a DSL root whose exec code is one lifted Rust
//! module (`#[lift] mod m;`, [`super::lifted`]) and emits that module's
//! source as-is; the crate path runs with [`Emission::Module`]:
//!
//! 1. the module file (under `src/`, not `lib.rs`/`main.rs`) is exactly
//!    `include!(concat!(env!("OUT_DIR"), "/<out>.rs"));` plus comments,
//!    where `<out>` is the file's stem (the directory name for `mod.rs`):
//!    nothing (no `use`, no attribute, no item) shares the module with the
//!    generated code;
//! 2. no other `.rs` file under `src/` mentions `"/<out>.rs"` (outside
//!    comments): the generated code is included by exactly one module file;
//! 3. the DSL root is not under `src/` (rustc must never compile the DSL
//!    sources as host code);
//! 4. the DSL root lifts exactly one exec module (a crate written in
//!    sandblaster's own dialect has no code to emit), and the module file's
//!    `//!` lines are the source's;
//! 5. the crate path runs unchanged — proofs, law audit, **every §15 gate**
//!    (the boundary is the root's `pub use` list: monomorphic, no `Irr`
//!    binders), the theorem gate, the lift conformance check. Any failure
//!    emits no code and fails the host build; there is no option.
//!
//! On success it writes `OUT_DIR/<out>.rs`, `OUT_DIR/<out>-report.json` and
//! `OUT_DIR/<out>-timing.json`.
//!
//! **Re-runs.** Check 2 reads the whole of `src/`, so the build script
//! re-runs on any host edit (`cargo::rerun-if-changed=src`). Only paths
//! that exist are watched ([`super::watch_existing`]): cargo re-runs a
//! build script on every invocation while a watched path is missing, and
//! the lift prelude's source-map paths are virtual. So that a host
//! edit does not re-verify an unchanged module, a verdict is reused when
//! the **verdict key** matches — a SHA-256 over the verifier's identity
//! (`context`: the facade passes [`super::cache::verifier_context`], a
//! content hash of the toolchain plus what else can change a result, never
//! the build-script binary), the target, the root, the module file, the
//! host edition (the lift conformance check compiles with it) and the
//! content of every file the front end read (sources, data files, the
//! lock) — and `OUT_DIR/<out>.rs` still has the SHA-256 recorded with the
//! key. Checks 1–4 and the front end run on every build; the proofs and
//! gates are skipped only for a byte-identical input set. The key file
//! lives in `OUT_DIR`, which only the build script writes (the same trust
//! as the generated file itself). Without a context (`None`) nothing is
//! reused.
//!
//! **The shared verdict cache** ([`super::cache`]): when `OUT_DIR` has no
//! matching key (a new target directory, `cargo clean`, another profile),
//! the verdict is looked up under the same key in the content-addressed
//! cache shared by every target directory and build; a hit writes the
//! cached file, report and timing (integrity-checked: a tampered entry is
//! rejected and the module re-verified). A new verdict is stored there. On
//! a miss the crate path also reuses the theorem gate's verdicts and the
//! conformance pass whose inputs did not change.

use std::path::{Path, PathBuf};

use super::cache::{Lookup, Store, VerdictCache};
use super::gates::{build_crate_emitting, Emission, LockUse};
use super::{check, strip_comments_ws, BuildOutcome};
use crate::loader::FileProvider;
use crate::surface::{hex, sha256};
use crate::target::TargetInfo;

/// The line a module file consists of (plus comments), for the output
/// `OUT_DIR/<out>.rs`.
pub fn module_include_line(out: &str) -> String {
    format!("include!(concat!(env!(\"OUT_DIR\"), \"/{out}.rs\"));")
}

/// Whether a module file's text is exactly the `include!` line of `out`
/// (plus comments and whitespace).
pub fn module_file_ok(text: &str, out: &str) -> bool {
    strip_comments_ws(text) == strip_comments_ws(&module_include_line(out))
}

/// The output name of the module file `module_file` (relative to the
/// manifest directory): its stem, or its directory's name for `mod.rs`.
/// It must be under `src/`, end in `.rs`, not be the crate root, and the
/// name must be a lowercase identifier other than `sandblaster` (reserved).
pub fn module_out_name(module_file: &str) -> Result<String, String> {
    let p = Path::new(module_file);
    let comps: Vec<String> = p.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    if p.is_absolute() || comps.first().map(String::as_str) != Some("src") || comps.len() < 2 || comps.iter().any(|c| c == ".." || c == ".") {
        return Err(format!("the module file `{module_file}` must be a relative path under `src/` (for example `src/verified/varint.rs`)"));
    }
    if p.extension().is_none_or(|x| x != "rs") {
        return Err(format!("the module file `{module_file}` must be a `.rs` file"));
    }
    if comps.len() == 2 && (comps[1] == "lib.rs" || comps[1] == "main.rs") {
        return Err(format!("the module file `{module_file}` is the crate root: a verified module is a module of the host crate"));
    }
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let name = if stem == "mod" {
        if comps.len() < 3 {
            return Err(format!("the module file `{module_file}` is `src/mod.rs`, which is not a module file"));
        }
        comps[comps.len() - 2].clone()
    } else {
        stem
    };
    let ident = name.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c == '_') && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !ident || name == "_" {
        return Err(format!("the module file `{module_file}` gives the output name `{name}`, which is not a lowercase identifier"));
    }
    if name == "sandblaster" {
        return Err(format!("the module file `{module_file}` gives the output name `sandblaster`, which is reserved"));
    }
    Ok(name)
}

/// The verdict key (module docs) of a build of `root` (`what` names the
/// emission: `module <file>\nout <name>` in module mode, the record and
/// the host inputs in place).
pub(crate) fn verdict_key(context: &str, env: &dyn Fn(&str) -> Option<String>, root: &Path, what: &str, c: &super::Checked) -> String {
    let mut t = String::from("sandblaster-module-verdict/2\n");
    t.push_str(&format!("context {}\n", hex(&sha256(context.as_bytes()))));
    for k in ["CARGO_CFG_TARGET_ARCH", "CARGO_CFG_TARGET_FEATURE", "CARGO_CFG_TARGET_ENDIAN", "CARGO_CFG_TARGET_POINTER_WIDTH"] {
        t.push_str(&format!("env {k}={}\n", env(k).unwrap_or_default()));
    }
    t.push_str(&format!("root {}\n{what}\n", root.display()));
    for (_, f) in c.sm.files() {
        t.push_str(&format!("file {} {}\n", f.path.display(), hex(&sha256(f.text.as_bytes()))));
    }
    t.push_str(&format!("lock {} {}\n", c.lock_path.display(), c.spec_lock.as_deref().map(|s| hex(&sha256(s.as_bytes()))).unwrap_or_else(|| "absent".into())));
    hex(&sha256(t.as_bytes()))
}

/// The shared cache the environment selects, for a build with a verifier
/// context (a disabled or unusable cache is a warning, never a failure).
pub(crate) fn open_cache(context: Option<&str>, env: &dyn Fn(&str) -> Option<String>, o: &mut BuildOutcome) -> Option<VerdictCache> {
    let ctx = context?;
    match Store::from_env(env) {
        Ok(Some(s)) => Some(VerdictCache::new(s, ctx)),
        Ok(None) => None,
        Err(e) => {
            o.cargo.push(format!("cargo::warning=sandblaster: verdict cache disabled: {}", e.replace('\n', " ")));
            None
        }
    }
}

/// A verdict of the shared cache under `key`: pushes the emitted file and
/// the other outputs (report, timing, in this order) and returns the
/// emitted file's SHA-256; `None` on a miss or a rejected entry (a
/// warning).
pub(crate) fn reuse_cached(vc: &VerdictCache, key: &str, code_path: &Path, others: &[PathBuf], o: &mut BuildOutcome) -> Option<String> {
    match vc.store.get("verdict", key) {
        Lookup::Hit(files) => {
            let get = |n: &str| files.iter().find(|(f, _)| f == n).map(|(_, t)| t.clone());
            let (Some(code), Some(report), Some(timing)) = (get("code"), get("report"), get("timing")) else {
                o.cargo.push("cargo::warning=sandblaster: verdict cache entry rejected (missing payload); verifying".into());
                return None;
            };
            let sha = hex(&sha256(code.as_bytes()));
            o.outputs.push((code_path.to_path_buf(), code));
            for (p, t) in others.iter().zip([report, timing]) {
                o.outputs.push((p.clone(), t));
            }
            Some(sha)
        }
        Lookup::Miss => None,
        Lookup::Rejected(why) => {
            o.cargo.push(format!("cargo::warning=sandblaster: verdict cache entry {}… rejected ({why}); verifying", &key[..16]));
            None
        }
    }
}

/// Stores a verdict in the shared cache (a failure is a warning).
pub(crate) fn store_cached(vc: &VerdictCache, key: &str, code: &str, report: &str, timing: &str, o: &mut BuildOutcome) {
    if let Err(e) = vc.store.put("verdict", key, &[("code", code), ("report", report), ("timing", timing)]) {
        o.cargo.push(format!("cargo::warning=sandblaster: verdict cache: {}", e.replace('\n', " ")));
    }
}

/// The key file's text.
pub(super) fn key_text(key: &str, code_sha: &str) -> String {
    format!("sandblaster-module-verdict/2\nkey {key}\nsha256 {code_sha}\n")
}

/// The build logic of `sandblaster::build::compile_module` (module docs):
/// verifies the DSL crate rooted at `root` and emits its lifted module for
/// the host's module file `module_file` (both relative to `CARGO_MANIFEST_DIR`).
/// `context` identifies the verifier for verdict reuse (`None`: never
/// reuse).
pub fn build_module(root: &str, module_file: &str, context: Option<&str>, env: &dyn Fn(&str) -> Option<String>, fs: &dyn FileProvider) -> BuildOutcome {
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
    for k in ["CARGO_CFG_TARGET_ARCH", "CARGO_CFG_TARGET_FEATURE", "CARGO_CFG_TARGET_ENDIAN", "CARGO_CFG_TARGET_POINTER_WIDTH"] {
        o.cargo.push(format!("cargo::rerun-if-env-changed={k}"));
    }
    let target = match TargetInfo::from_cargo_env(env) {
        Ok(t) => t,
        Err(e) => return fail(o, e),
    };
    let out = match module_out_name(module_file) {
        Ok(n) => n,
        Err(e) => return fail(o, e),
    };
    // 1. the module file is exactly the include line
    let src = manifest.join("src");
    let mfile = manifest.join(module_file);
    o.cargo.push(format!("cargo::rerun-if-changed={}", src.display()));
    let line = module_include_line(&out);
    let module_text = match fs.read(&mfile) {
        Ok(text) if module_file_ok(&text, &out) => text,
        Ok(_) => return fail(o, format!("`{}` must contain exactly `{line}` (plus comments): the verified module shares its module with nothing, so host code cannot live next to generated code, import names into it or include an unverified file in its place (DESIGN.md §2.1)", mfile.display())),
        Err(e) => return fail(o, format!("cannot read the module file `{}`: {e}", mfile.display())),
    };
    // 2. no other file includes the generated module
    let needle = format!("\"/{out}.rs\"");
    let files = match fs.list_rs(&src) {
        Ok(f) => f,
        Err(e) => return fail(o, format!("cannot list `{}`: {e}", src.display())),
    };
    let norm = crate::loader::normalize(&mfile);
    for f in files {
        if crate::loader::normalize(&f) == norm {
            continue;
        }
        match fs.read(&f) {
            Ok(text) if strip_comments_ws(&text).contains(&needle) => {
                return fail(o, format!("`{}` also mentions `OUT_DIR/{out}.rs`: the verified module must be included by exactly one module file, `{}`, whose only content is `{line}` (DESIGN.md §2.1)", f.display(), mfile.display()));
            }
            Ok(_) => {}
            Err(e) => return fail(o, format!("cannot read `{}`: {e}", f.display())),
        }
    }
    // 3. the DSL root is not host source
    let root_path = manifest.join(root);
    if crate::loader::normalize(&root_path).starts_with(crate::loader::normalize(&src)) {
        return fail(o, format!("the DSL root `{root}` is under `src/`: rustc would see the DSL sources as host code; put them beside `src/` (for example `sandblaster/{out}/mod.rs`)"));
    }
    if let Some(dir) = root_path.parent() {
        o.cargo.push(format!("cargo::rerun-if-changed={}", dir.display()));
    }
    let mut checked = check(&root_path, fs, &target);
    super::watch_existing(&mut o, fs, checked.sm.files().map(|(_, f)| f.path.as_path()).chain([checked.lock_path.as_path()]));
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
    // 4. the lifted module (`driver::lifted`): the module file's `//!` lines
    // are the source's leading `//!` lines, so module file + emitted body
    // is the source file
    match super::lifted::emitted_module(&checked.lifted) {
        Err(e) => return fail(o, e),
        Ok(Some(info)) => {
            let src = checked.sm.get(info.file).map(|f| f.text.as_str()).unwrap_or("");
            if !super::lifted::module_file_docs_ok(&module_text, src) {
                return fail(o, format!("`{}` must carry exactly the leading `//!` lines of the lifted source `{}` (its module docs; an `include!`d file cannot hold them) before the include line: module file + emitted code is the source as-is (DESIGN.md §2.1)", mfile.display(), checked.sm.path(info.file).display()));
            }
        }
        Ok(None) => return fail(o, format!("`{root}` lifts no Rust module (`#[lift] mod m;`): module mode emits a lifted module's source as-is, and a crate written in sandblaster's own dialect has no code to emit (check it with `sandblaster check`)")),
    }
    o.cargo.push("cargo::rerun-if-env-changed=SANDBLASTER_MEM_LIMIT_GB".into());
    o.cargo.push("cargo::rerun-if-env-changed=RUSTC".into());
    let code_path = out_dir.join(format!("{out}.rs"));
    let key_path = out_dir.join(format!("{out}-verdict.key"));
    let root_display = root_path.display().to_string();
    let conform = crate::conform::Config::for_build(env, fs, &manifest, &out_dir, &out, context);
    let key = context.map(|ctx| verdict_key(ctx, env, &root_path, &format!("module {module_file}\nout {out}\nedition {}", conform.edition), &checked));
    // verdict reuse: the same inputs, and the emitted file unchanged
    if let Some(k) = &key
        && let (Ok(kt), Ok(code)) = (fs.read(&key_path), fs.read(&code_path))
        && kt == key_text(k, &hex(&sha256(code.as_bytes())))
    {
        o.cargo.push(format!("cargo::warning=sandblaster: verified module `{out}` unchanged (verdict key {}): reusing `{}`", &k[..16], code_path.display()));
        o.ok = true;
        return o;
    }
    // the shared verdict cache (module docs)
    let cache = open_cache(context, env, &mut o);
    if let (Some(k), Some(vc)) = (&key, &cache) {
        match reuse_cached(vc, k, &code_path, &[out_dir.join(format!("{out}-report.json")), out_dir.join(format!("{out}-timing.json"))], &mut o) {
            Some(sha) => {
                o.outputs.push((key_path, key_text(k, &sha)));
                o.cargo.push(format!("cargo::warning=sandblaster: verified module `{out}` unchanged (verdict key {}): reusing the verdict cache entry in `{}`", &k[..16], vc.store.dir().display()));
                o.ok = true;
                return o;
            }
            None => checked.cache = Some(std::sync::Arc::new(vc.clone())),
        }
    }
    let b = build_crate_emitting(&checked, LockUse::Enforce, &root_display, &Emission::Module { module_file: module_file.to_string(), out: format!("{out}.rs"), conform });
    o.outputs.push((out_dir.join(format!("{out}-report.json")), b.report.clone()));
    o.outputs.push((out_dir.join(format!("{out}-timing.json")), b.timing.clone()));
    let Some(verdict) = &b.verdict else {
        o.stderr.push_str(&b.render_failure(&checked, &root_display));
        // a failed build leaves no reusable verdict behind
        o.outputs.push((key_path, String::new()));
        o.ok = false;
        return o;
    };
    o.outputs.insert(0, (code_path, verdict.code().to_string()));
    if let Some(k) = &key {
        o.outputs.push((key_path, key_text(k, &verdict.code_sha256())));
        if let Some(vc) = &cache {
            store_cached(vc, k, verdict.code(), &b.report, &b.timing, &mut o);
        }
    }
    o.cargo.push(format!("cargo::warning=sandblaster: verified module `{out}` (`{root}`, included by `{module_file}`): {}", verdict.summary()));
    o.ok = true;
    o
}
