//! `sandblaster::build::compile` — the `build.rs` entry point (DESIGN.md §10.1);
//! [`compile_module`] is module mode's (a verified module inside an ordinary
//! crate, DESIGN.md §2.1).
//!
//! ```ignore
//! // build.rs of a sandblaster crate
//! fn main() {
//!     sandblaster::build::compile("sandblaster/mod.rs");
//! }
//! ```
//!
//! Behaviour (see [`sandblaster_front::driver::build_verified`] and the crate
//! path [`sandblaster_front::driver::build_crate`]):
//!
//! * reads `CARGO_MANIFEST_DIR`, `OUT_DIR` and the `CARGO_CFG_TARGET_*`
//!   variables (never the host);
//! * requires `src/lib.rs` to be exactly
//!   `include!(concat!(env!("OUT_DIR"), "/sandblaster.rs"));` (plus comments);
//! * loads, resolves, type checks and validates the DSL crate rooted at `root`
//!   (relative to the manifest directory);
//! * elaborates every item to the kernel's core language, proves every
//!   obligation (automation plus the crate's proof scripts) and has the
//!   kernel check every definition and law — on a dedicated thread with a
//!   512 MiB stack — and audits the laws for vacuity;
//! * runs **every §15 gate** (DESIGN.md §15.8): the boundary is exactly the
//!   root's `pub use` list; every spec function is exercised by examples
//!   with each outcome, and specifications are spec-closed; every section is
//!   fully specified; the law rules LR1–LR10; the specification surface
//!   equals the root's lock (`SPEC.lock`, or `SPEC.<stem>.lock` for a root
//!   not named `mod.rs`/`lib.rs`); every spec mutant is killed by an example
//!   or a law counterexample;
//! * runs the optimizer (always; DESIGN.md §8.2): `VariantEquiv` of the
//!   hardware variants (kernel-checked `BvRefl`), multiversioned call trees
//!   dispatched once at the boundary (only variants with hardware evidence),
//!   symbolic-execution specialization admitted by `check_residual_equal`,
//!   proven bounds checks printed as `get_unchecked`; optimizer failures are
//!   `cargo::warning`s with the proven unspecialized code as fallback, or
//!   errors when `SANDBLASTER_STRICT_OPT=1`;
//! * prints the canonical code and **round-trips** it (DESIGN.md §8.3):
//!   the printed file is read back, elaborated in generated mode and
//!   compared with the optimized core; a mismatch is a build error; then
//!   cross-checks the emission chain;
//! * caps its own heap (`SANDBLASTER_MEM_LIMIT_GB`, see `sandblaster-memguard`);
//! * prints `cargo::rerun-if-changed` for every file read and for the lock;
//! * on failure prints the diagnostics (goal, facts, what automation tried,
//!   each gate's errors) and exits with status 1 — **no code is emitted**,
//!   and there is no option to skip proofs, a gate or the optimizer;
//! * on success writes `OUT_DIR/sandblaster.rs` (marked `VERIFIED + OPTIMIZED
//!   (phase 3)`) and `OUT_DIR/sandblaster-report.json` (obligations, laws,
//!   each gate's outcome, specializations with reasons, variants with their
//!   model evidence, clones, dispatchers, round-trip statistics, the lock
//!   status and the SHA-256 of the emitted file);
//! * exports the lock's Merkle root as `SANDBLASTER_SPEC_ROOT`. It **never
//!   writes the lock** — only `sandblaster spec --accept` does, after every
//!   other gate passed, and no environment variable changes that.

extern crate std;

use std::io::Write as _;
use std::string::String;
use std::vec::Vec;

use sandblaster_front::driver;
use sandblaster_front::loader::RealFs;

/// Verifies the DSL crate rooted at `root` and writes the generated code to
/// `OUT_DIR`. Exits the process with status 1 on failure.
pub fn compile(root: &str) {
    // resource safety: cap the build script's heap (SANDBLASTER_MEM_LIMIT_GB,
    // default 8 GiB hard / 6 GiB soft; sandblaster-memguard is not in the TCB:
    // hitting a limit can only make the build fail, never succeed)
    sandblaster_front::memguard::init_from_env();
    let env = |k: &str| std::env::var(k).ok();
    let context = verifier_context();
    finish(driver::build_verified_with(root, context.as_deref(), &env, &RealFs));
}

/// Module mode (DESIGN.md §2.1): verifies the DSL crate rooted at `root` and
/// writes it, relocated, to `OUT_DIR/<out>.rs` for the host crate's
/// `module_file`, which must be exactly
/// `include!(concat!(env!("OUT_DIR"), "/<out>.rs"));` (plus comments), where
/// `<out>` is the module file's stem (its directory's name for `mod.rs`).
/// The rest of the host crate is ordinary Rust.
///
/// ```ignore
/// // build.rs of a host crate
/// fn main() {
///     sandblaster::build::compile_module("sandblaster/varint/mod.rs", "src/verified/varint.rs");
/// }
/// ```
///
/// Everything [`compile`] runs — proofs, every §15 gate, the optimizer, the
/// round trip, the emission-chain check — runs here too, plus the module
/// checks (the module file is exactly the `include!` line, no other file
/// under `src/` includes the output, the DSL root is outside `src/`) and the
/// checked relocation (`sandblaster_front::relocate`). A failure exits with
/// status 1, so the host crate does not build. There is no option. Call it
/// once per verified module; two calls with the same output name fail.
pub fn compile_module(root: &str, module_file: &str) {
    sandblaster_front::memguard::init_from_env();
    static SEEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    if let Ok(out) = driver::module_out_name(module_file) {
        let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains(&out) {
            let _ = writeln!(std::io::stderr(), "error[build]: two verified modules write `OUT_DIR/{out}.rs` (`compile_module` for `{module_file}` again): each module file needs its own output name");
            std::process::exit(1);
        }
        seen.push(out);
    }
    let env = |k: &str| std::env::var(k).ok();
    let context = verifier_context();
    finish(driver::build_module(root, module_file, context.as_deref(), &env, &RealFs));
}

/// In-place lifted modules (DESIGN.md §2.1 "in place"): verifies the DSL
/// crate rooted at `root`, whose `#[lift(in_place)]` modules are the host
/// crate's own files, and writes the record `OUT_DIR/<name>-verified.txt`
/// (plus `-report.json` and `-timing.json`), and the lowered copy of every
/// in-place file (`OUT_DIR/<name>-lowered__<path>`: the file with the
/// proven optimizer's checked rewrites). rustc compiles the files the
/// verifier read, or a file's lowered copy where the host declares the
/// module by its lowered declaration (DESIGN.md §2.1, "Compiling the
/// optimized output"). Every proof, every §15 gate and the lift
/// conformance check run as in [`compile_module`]; a failure exits with
/// status 1, so the host crate does not build (and every copy is a
/// `compile_error!` stub).
///
/// ```ignore
/// // build.rs of a host crate
/// fn main() {
///     sandblaster::build::compile_lifted("sandblaster/mmr/mod.rs", "mmr");
/// }
/// ```
pub fn compile_lifted(root: &str, name: &str) {
    sandblaster_front::memguard::init_from_env();
    let env = |k: &str| std::env::var(k).ok();
    let context = verifier_context();
    finish(driver::build_lifted(root, name, context.as_deref(), &env, &RealFs));
}

/// **Development aid — to be removed before any landing (DESIGN.md §2.1,
/// §15.8: no opt-out).** [`compile_lifted`] with the §15 gates reported
/// but not enforced, for a lifted crate whose specification lock is not
/// accepted yet. Every proof and law must still check (a failure fails the
/// build). It never produces a verdict, an accept permit or a reusable
/// verdict key: it writes `OUT_DIR/<name>-pending.txt`, whose first line
/// is `NOT VERIFIED — DEVELOPMENT BUILD: PROOFS CHECKED, §15 GATES
/// PENDING`, overwrites `OUT_DIR/<name>-verified.txt` with a `NOT
/// VERIFIED` stub (no verified record of an earlier build survives), marks
/// `<name>-report.json` with the same status, and prints a `cargo::warning`
/// on every build. The lift conformance check (it runs after the gates) is
/// reported as not run unless every gate passed. Switch to
/// [`compile_lifted`] once the lock is accepted.
pub fn compile_lifted_pending_gates(root: &str, name: &str) {
    sandblaster_front::memguard::init_from_env();
    let env = |k: &str| std::env::var(k).ok();
    let context = verifier_context();
    finish(driver::build_lifted_with(root, name, context.as_deref(), &env, &RealFs, driver::GateUse::Pending));
}

/// The toolchain identity: a content hash of the toolchain this build
/// script links (the facade's `build.rs`, `toolchain_id.rs`), empty when it
/// could not be computed (then no verdict is reused).
const TOOLCHAIN_ID: &str = env!("SANDBLASTER_TOOLCHAIN_ID");

/// The verifier's identity for verdict reuse (the local key file in
/// `OUT_DIR`, the shared verdict cache and the lift conformance key;
/// [`sandblaster_front::driver::cache::verifier_context`]): the toolchain's
/// content hash, its overflow checks and test hooks, the build's `rustc
/// -vV` and every `SANDBLASTER_*` variable but the resource and cache
/// settings. It does not depend on this binary, the host crate's features,
/// the profile or the target directory, so `cargo build`, `cargo test`, a
/// release build and a dependent crate's build share one verdict. `None`
/// (never reuse) without a toolchain identity.
fn verifier_context() -> Option<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let vv = std::process::Command::new(&rustc).arg("-vV").output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    let vars: Vec<(String, String)> = std::env::vars().collect();
    sandblaster_front::driver::cache::verifier_context(TOOLCHAIN_ID, vv.as_deref(), &vars)
}

fn finish(outcome: driver::BuildOutcome) {
    let mut stdout = std::io::stdout().lock();
    for line in &outcome.cargo {
        let _ = writeln!(stdout, "{line}");
    }
    let _ = stdout.flush();
    if !outcome.stderr.is_empty() {
        let _ = write!(std::io::stderr(), "{}", outcome.stderr);
    }
    let write = |path: &std::path::Path, contents: &str| if outcome.guarded.iter().any(|g| g == path) { write_guarded(path, contents) } else { std::fs::write(path, contents) };
    if !outcome.ok {
        // the report of a failed verification helps diagnosing it (and a
        // lowered copy of a failed build is a `compile_error!` stub)
        for (path, contents) in &outcome.outputs {
            let _ = write(path, contents);
        }
        std::process::exit(1);
    }
    for (path, contents) in &outcome.outputs {
        if let Err(e) = write(path, contents) {
            let _ = writeln!(std::io::stderr(), "error[build]: cannot write `{}`: {e}", path.display());
            std::process::exit(1);
        }
    }
}

/// Writes a guarded output (`BuildOutcome::guarded`: a lowered copy rustc
/// compiles, which the build script watches): read-only (Unix), with the
/// modification time `GUARDED_MTIME_SECS`. cargo re-runs a build script when
/// a watched file is newer than the script's last run; a file the script
/// itself wrote is newer, so without the old time every build would re-run
/// it. With it, only a later edit of the copy re-runs the script, which
/// rewrites the copy from the verified source before rustc compiles it.
fn write_guarded(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
        }
    }
    std::fs::write(path, contents)?;
    let f = std::fs::File::options().write(true).open(path)?;
    f.set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(driver::GUARDED_MTIME_SECS))?;
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A guarded output is written read-only with the old time, and a
    /// rewrite replaces it (the build script rewrites an edited copy);
    /// the twin: a plain write leaves the current time.
    #[test]
    fn guarded_outputs_are_old_and_read_only() {
        let dir = std::env::temp_dir().join(std::format!("sandblaster-guarded-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("m-lowered__a.rs");
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(driver::GUARDED_MTIME_SECS);
        write_guarded(&p, "fn a() {}\n").unwrap();
        let m = std::fs::metadata(&p).unwrap();
        assert_eq!(m.modified().unwrap(), old);
        assert!(m.permissions().readonly());
        // an edit (made writable, as an editor that overrides read-only
        // would) is newer than any build script run
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        std::fs::write(&p, "fn a() { evil() }\n").unwrap();
        assert!(std::fs::metadata(&p).unwrap().modified().unwrap() > old);
        // the re-run rewrites it over a read-only file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        write_guarded(&p, "fn a() {}\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "fn a() {}\n");
        assert_eq!(std::fs::metadata(&p).unwrap().modified().unwrap(), old);
        // twin: an ordinary output keeps its write time
        let q = dir.join("m-report.json");
        std::fs::write(&q, "{}").unwrap();
        assert!(std::fs::metadata(&q).unwrap().modified().unwrap() > old);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
