//! In-place lifted modules (DESIGN.md §2.1 "in place", SEMANTICS.md §19.5):
//! `sandblaster::build::compile_lifted(root, name)` verifies a DSL root whose
//! lifted exec modules are the host crate's own files
//! (`#[lift(in_place)] #[path = "../../src/x.rs"] mod x;`). Nothing is
//! emitted: rustc compiles the very files the verifier read. The build
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
//!    `mod <name>;` and has no `#[path]` attribute, so rustc compiles the
//!    file the verifier read (textual: it catches mistakes, not a host
//!    that deliberately hides a `#[path]`, as module mode's scan).
//!
//! Re-runs and verdict reuse are module mode's ([`super::module`]): the
//! build script re-runs on any edit under `src/`; the verdict is reused
//! when the verdict key (toolchain, environment, target, root, name and
//! the content of every file the front end read — the in-place files
//! included) matches and the record still has its recorded hash.

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
    // 3, 4. the in-place files are host source, declared plainly
    let nsrc = crate::loader::normalize(&src);
    let in_place: Vec<&crate::lift::LiftedInfo> = checked.lifted.iter().filter(|l| l.in_place && !l.ghost).collect();
    if in_place.is_empty() {
        return fail(o, format!("`{root}` has no `#[lift(in_place)]` module: `compile_lifted` verifies the host's own files (use `compile_module` for an emitted module)"));
    }
    for l in &in_place {
        let p = crate::loader::normalize(checked.sm.path(l.file));
        if !p.starts_with(&nsrc) {
            return fail(o, format!("the in-place lifted module `{}` reads `{}`, which is not under `src/`: an in-place module is the host's own file", l.name, p.display()));
        }
        match declaring_file(fs, &nsrc, &p) {
            Some((decl, m)) => match fs.read(&decl) {
                Ok(text) if declares_plain(&text, &m) => {}
                Ok(_) => return fail(o, format!("`{}` must declare `mod {m};` without `#[path]`, so that rustc compiles `{}`, the file verified in place", decl.display(), p.display())),
                Err(e) => return fail(o, format!("cannot read `{}`: {e}", decl.display())),
            },
            None => return fail(o, format!("no host file declares the in-place module `{}` (`{}`)", l.name, p.display())),
        }
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
        && kt == key_text(k, &hex(&sha256(code.as_bytes())))
    {
        o.cargo.push(format!("cargo::warning=sandblaster: `{name}` verified in place, unchanged (verdict key {}): reusing `{}`", &k[..16], code_path.display()));
        o.ok = true;
        return o;
    }
    let root_display = root_path.display().to_string();
    let b = build_crate_emitting(&checked, LockUse::Enforce, &root_display, &Emission::InPlace { out: out.clone(), conform });
    if gates == GateUse::Pending {
        let status = format!("{PENDING_STATUS} (a lowered preview: rustc compiles `src/` as is)");
        o.outputs.extend(lowered_outputs(&b, &out_dir, &src, name, &root_display, &status));
        return pending_outcome(o, &b, &checked, name, root, &root_display, &out_dir, &code_path, &key_path);
    }
    let status = if b.verdict.is_some() { "VERIFIED + LIFTED IN PLACE + OPTIMIZED (the lowered copy of a verified file; rustc compiles `src/` as is)".to_string() } else { "NOT VERIFIED (the build issued no verdict; rustc compiles `src/` as is)".to_string() };
    o.outputs.extend(lowered_outputs(&b, &out_dir, &src, name, &root_display, &status));
    o.outputs.push((out_dir.join(format!("{name}-report.json")), b.report.clone()));
    o.outputs.push((out_dir.join(format!("{name}-timing.json")), b.timing.clone()));
    let Some(verdict) = &b.verdict else {
        o.stderr.push_str(&b.render_failure(&checked, &root_display));
        o.outputs.push((key_path, String::new()));
        o.ok = false;
        return o;
    };
    o.outputs.insert(0, (code_path, verdict.code().to_string()));
    if let Some(k) = &key {
        o.outputs.push((key_path, key_text(k, &verdict.code_sha256())));
    }
    o.cargo.push(format!("cargo::warning=sandblaster: `{name}` verified in place (`{root}`): {}", verdict.summary()));
    o.ok = true;
    o
}

/// The lowered copies of the in-place files the optimizer rewrote
/// (`OUT_DIR/<name>-lowered__<path under src/, `/` as `__`>`, DESIGN.md
/// §2.1): each is the
/// host file with the rewritten functions' bodies calling their checked
/// replacements, appended; a header says what was rewritten and the
/// build's `status`. And the index `OUT_DIR/<name>-lowered.txt` (always
/// written, so no copy of an earlier build is mistaken for this one's).
fn lowered_outputs(b: &super::gates::CrateBuild, out_dir: &Path, src: &Path, name: &str, root_display: &str, status: &str) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut index = format!("{status}\nsandblaster lowered copies of `{name}` ({root_display}): the host's files with functions rewritten to their optimizer replacements (kernel-checked links, lifted round trip)\n");
    let nsrc = crate::loader::normalize(src);
    for l in &b.lowered_in_place {
        if l.lowered() == 0 {
            continue;
        }
        let file = PathBuf::from(&l.file);
        let Ok(rel) = file.strip_prefix(&nsrc) else { continue };
        // a flat name (the build writes files, not directories)
        let flat = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("__");
        let dst = out_dir.join(format!("{name}-lowered__{flat}"));
        let mut head = format!("// @generated by sandblaster from `{root_display}`. Do not edit.\n// STATUS: {status}\n// The code below is `{}` except the bodies of the functions listed here: each calls its replacement,\n// appended at the end, kernel-checked equal to the function and read back by the lift (DESIGN.md §2.1).\n", l.file);
        for r in &l.records {
            if let super::lowered::LowerOutcome::Lowered { rung, cost_source, cost_residual, via, .. } = &r.outcome {
                let via = if via.is_empty() { String::new() } else { format!("; {via}") };
                let line = format!("rewritten: `{}` (rung {rung}; portable cost {cost_source} -> {cost_residual} milli-cycles{via})", r.function);
                head.push_str(&format!("//   {line}\n"));
                index.push_str(&format!("{}: {line}\n", dst.display()));
            }
        }
        out.push((dst, format!("{head}{}", l.text())));
    }
    out.push((out_dir.join(format!("{name}-lowered.txt")), index));
    out
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
}
