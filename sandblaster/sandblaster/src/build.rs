//! The `build.rs` entry points (DESIGN.md §10.1, §2.1): [`compile_module`]
//! (a verified lifted module inside an ordinary crate, emitted as its source
//! as-is) and [`compile_lifted`] (the host crate's own files verified in
//! place, where rustc compiles them).
//!
//! ```ignore
//! // build.rs of a host crate
//! fn main() {
//!     sandblaster::build::compile_lifted("sandblaster/mmr/mod.rs", "mmr");
//! }
//! ```
//!
//! Behaviour (see [`sandblaster_front::driver::build_module`],
//! [`sandblaster_front::driver::build_lifted`] and the crate path
//! [`sandblaster_front::driver::build_crate`]):
//!
//! * reads `CARGO_MANIFEST_DIR`, `OUT_DIR` and the `CARGO_CFG_TARGET_*`
//!   variables (never the host);
//! * loads, resolves, type checks and validates the DSL crate rooted at `root`
//!   (relative to the manifest directory), with its lifted Rust: the item
//!   skeleton from the source, the function bodies from rustc's MIR (the
//!   checked-in `.sbmir`);
//! * elaborates every item to the kernel's core language, proves every
//!   obligation (automation plus the crate's proof scripts) and has the
//!   kernel check every definition and law — on a dedicated thread with a
//!   512 MiB stack — and audits the laws for vacuity;
//! * runs **every §15 gate** (DESIGN.md §15.8): the boundary is exactly the
//!   root's `pub use` list; every spec function is exercised by examples
//!   with each outcome, and specifications are spec-closed; every section is
//!   fully specified; the law rules LR1–LR10 but LR8; the specification
//!   surface equals the root's lock (`SPEC.lock`, or `SPEC.<stem>.lock` for
//!   a root not named `mod.rs`/`lib.rs`). (Spec mutation and LR8 are the
//!   on-demand tool `sandblaster mutate`, not part of the build);
//! * proves every lifted function's theorem relating rustc's MIR to the
//!   structured reading the laws are about (the theorem gate), and checks
//!   the lift against rustc's build of the source (the lift conformance
//!   check);
//! * caps its own heap (`SANDBLASTER_MEM_LIMIT_GB`, see `sandblaster-memguard`);
//! * prints `cargo::rerun-if-changed` for every file read and for the lock;
//! * on failure prints the diagnostics (goal, facts, what automation tried,
//!   each gate's errors) and exits with status 1 — **no verdict is
//!   written**, and there is no option to skip a proof or a gate;
//! * on success writes the verdict (`OUT_DIR/<out>.rs` in module mode, the
//!   record `OUT_DIR/<name>-verified.txt` in place) and the report
//!   (obligations, laws, each gate's outcome, the theorems, the lift
//!   conformance check, the lock status and the SHA-256 of the emitted
//!   file). It **never writes the lock** — only `sandblaster spec --accept`
//!   does, after every other gate passed, and no environment variable
//!   changes that.

extern crate std;

use std::io::Write as _;
use std::string::String;
use std::vec::Vec;

use sandblaster_front::driver;
use sandblaster_front::loader::RealFs;

/// Module mode (DESIGN.md §2.1): verifies the DSL crate rooted at `root`,
/// whose exec code is one lifted Rust module, and writes that module's
/// source as-is to `OUT_DIR/<out>.rs` for the host crate's `module_file`,
/// which must be exactly
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
/// Proofs, every §15 gate, the theorem gate and the lift conformance check
/// run, plus the module checks (the module file is exactly the `include!`
/// line, no other file under `src/` includes the output, the DSL root is
/// outside `src/`). A failure exits with status 1, so the host crate does
/// not build. There is no option. Call it once per verified module; two
/// calls with the same output name fail.
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
/// (plus `-report.json` and `-timing.json`). rustc compiles the files the
/// verifier read, as written: each in-place module is declared `mod m;`.
/// Every proof, every §15 gate and the lift conformance check run as in
/// [`compile_module`]; a failure exits with status 1, so the host crate does
/// not build.
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

/// The toolchain identity: a content hash of the toolchain this build
/// script links (the facade's `build.rs`, `toolchain_id.rs`), empty when it
/// could not be computed (then no verdict is reused).
const TOOLCHAIN_ID: &str = env!("SANDBLASTER_TOOLCHAIN_ID");

/// The verifier's identity for verdict reuse (the local key file in
/// `OUT_DIR`, the shared verdict cache and the lift conformance key;
/// [`sandblaster_front::driver::cache::verifier_context`]): the toolchain's
/// content hash, its overflow checks, the build's `rustc
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
