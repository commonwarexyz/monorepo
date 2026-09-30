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
use std::format;

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
/// (plus `-report.json` and `-timing.json`). Nothing is emitted or
/// included: rustc compiles the files the verifier read. Every proof,
/// every §15 gate and the lift conformance check run as in
/// [`compile_module`] (the proven optimizer cannot rewrite the host's own
/// files, so nothing is lowered); a failure exits with status 1, so the
/// host crate does not build.
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

/// Resource and cache settings: they never change a result, so they are
/// not part of the verifier's identity (a build with another memory limit
/// or cache directory reuses the same verdicts).
const NOT_IDENTITY: &[&str] = &["SANDBLASTER_MEM_LIMIT_GB", "SANDBLASTER_GATE_WORKERS", "SANDBLASTER_CACHE", "SANDBLASTER_CACHE_DIR", "SANDBLASTER_CACHE_KEY", "SANDBLASTER_CACHE_KEY_FILE", "SANDBLASTER_CACHE_MAX_MB"];

/// The verifier's identity for verdict reuse (the local key file in
/// `OUT_DIR` and the shared verdict cache, `sandblaster_front::driver::cache`):
/// the SHA-256 of this build-script binary (it embeds the whole toolchain
/// and its dependencies, so any toolchain change re-verifies; it does not
/// depend on the target directory) and every `SANDBLASTER_*` variable but the
/// resource and cache settings (the others may steer the optimizer).
/// `None` (never reuse) when the binary cannot be read.
fn verifier_context() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let bytes = std::fs::read(exe).ok()?;
    let mut ctx = format!("exe {}\n", sandblaster_front::surface::hex(&sandblaster_front::surface::sha256(&bytes)));
    let mut vars: Vec<(String, String)> = std::env::vars().filter(|(k, _)| k.starts_with("SANDBLASTER_") && !NOT_IDENTITY.contains(&k.as_str())).collect();
    vars.sort();
    for (k, v) in vars {
        ctx.push_str(&format!("{k}={v}\n"));
    }
    Some(ctx)
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
    if !outcome.ok {
        // the report of a failed verification helps diagnosing it
        for (path, contents) in &outcome.outputs {
            let _ = std::fs::write(path, contents);
        }
        std::process::exit(1);
    }
    for (path, contents) in &outcome.outputs {
        if let Err(e) = std::fs::write(path, contents) {
            let _ = writeln!(std::io::stderr(), "error[build]: cannot write `{}`: {e}", path.display());
            std::process::exit(1);
        }
    }
}
