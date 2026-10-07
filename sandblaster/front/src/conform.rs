//! Lift conformance (DESIGN.md §1.1 item 8): the
//! differential check of the lift — the trusted translation of an existing
//! Rust file into the exec subset ([`crate::lift`]) — against `rustc`,
//! run by every module-mode build of a lifted module before its verdict is
//! sealed.
//!
//! For every lifted exec function of the emitted module (the lift records
//! each one with the original item it stands for, [`crate::lift::ConformEntry`]):
//!
//! 1. **Inputs.** Deterministic, seeded, coverage-driven: candidate values
//!    by parameter type from the counterexample engine's generator
//!    ([`crate::mutate::eval::pool`]: the crate's constants, boundary
//!    values, patterns of byte sequences, pseudo-random values) plus every
//!    power of two ±1 of each integer width and every value up to 64;
//!    values of an invariant-carrying struct built field by field and kept
//!    only when the invariant holds (the kernel decides it), plus every value of that type an evaluation
//!    produced (states reached from constructors), tried first; the bytes
//!    each call put into a `BufMut` (what the module writes) are candidates
//!    for the parameters that read buffers; then mutants (bit flips,
//!    ±1, bytes appended, removed or changed) of the inputs whose outputs
//!    showed a new *outcome class* (the shape of each output — variant,
//!    bit length of each integer, bytes consumed or appended — and of each
//!    scalar input), until the per-function budget is spent (400 kernel
//!    evaluations, over four rounds: what one round found seeds the next).
//! 2. **The lifted model** is evaluated by the kernel: `Env::eval_closed`
//!    (TCB) when the arguments are closed well-typed terms, else (an
//!    argument with an invariant carries erased proofs) the reference
//!    strategy of `sandblaster eval` (the kernel's evaluator, every
//!    definition transparent, stuck recursive applications completed).
//! 3. **The original** — the source file byte for byte, compiled by the
//!    build's `rustc` with overflow checks and debug assertions — is called
//!    on the same inputs by a generated harness: the source is a module of
//!    a harness crate whose root holds the host traits the lift knows with
//!    the signatures it assumes (`lift/conform_host.rs`), the
//!    `#[lift(host)]` models, and the crate `bytes` as the buffer model in
//!    Rust (`lift/conform_bytes.rs`: `BufMut` is a `Vec<u8>` of the bytes
//!    put so far, `Buf` a `&[u8]` of the bytes not yet read); a child
//!    module appended to the copy calls each original (private items
//!    included) and prints the states and the result.
//! 4. **Comparison.** Every state (`&mut self`, each buffer, and §19.10's
//!    states: a `&mut` value, a `&mut Vec<T>`, an `Option<&mut Vec<T>>`, and
//!    the byte strings a byte-string iterator has not yielded, driven by a
//!    slice iterator) and the result must be equal; an in-place harness
//!    passes a library newtype the lift reads as its field (a host model,
//!    SEMANTICS.md §19.10: SHA-256's `Digest`) through `__cv`; a panic in `rustc`'s build, a kernel evaluation that
//!    does not finish, or a harness that does not compile is a failure.
//!    Any failure fails the build and names the function, the input and
//!    both outputs.
//! 5. **Panic contracts** (in place, DESIGN.md §16.5). After step 1 the
//!    check seeks inputs inside each panic contract's panic region on
//!    purpose (where its domain holds and its no-panic clause does not:
//!    [`PANIC_INPUTS`] of them, from the parameters' pools and mutants,
//!    deciding each by the precondition checkers only); on those rustc must
//!    panic and the literal reading must give `Panic`. A function returning
//!    `impl Trait` is compared there only (its result is opaque). A panic
//!    contract compared on no input fails the check: this also catches a
//!    condition that never holds on the function's domain, whose panic
//!    theorem would hold vacuously.
//!
//! Bounded (a fixed evaluation budget per function; seconds for the varint
//! pilot's 64 functions) and cached: a pass is recorded in the work
//! directory and in the shared verdict cache (`driver::cache`, namespace
//! [`CACHE_NS`]) under a key over this check's version, the toolchain
//! identity, the source, the host models, both shims, the entries, the
//! edition, `rustc -vV`, the MIR and contracts the literal reading reads,
//! and a position-independent fingerprint of every item of the DSL crate
//! but its laws, lemmas and proofs ([`items_key`]: the input pools draw on
//! the crate's constants, the precondition checkers call its spec
//! functions); the same key skips the check and replays the recorded
//! report ([`Record`]), so the report, its summary and the emitted header
//! are the same bytes whether the check ran or was cached (the wall-clock
//! time is not part of any of them).
//!
//! What it does not show: that the host's real `Buf`/`BufMut` behave as
//! the buffer model (the shim is compared with the real `bytes` crate by
//! the pilot's `vshim` binary), and behaviour outside the generated inputs
//! (the check is a test, not a proof: DESIGN.md §1.1 lists the lift as
//! trusted).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sandblaster_kernel::term::{GlobalId, Lvl, Rel, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Budget, VEnv};

use crate::driver::Checked;
use crate::elab::value::{Conv, J};
use crate::elab::{self};
use crate::hir::*;
use crate::json::Json;
use crate::lift::{ConformCallee, ConformEntry, LiftedInfo, ParamPass};
use crate::mutate::eval::{self as meval, Hints, Rng, Val};
use crate::surface::{hex, sha256};

mod in_place;
mod literal;
pub use in_place::{check_in_place, host_inputs, HostInputs};
pub use literal::LITERAL_CASES;

/// This check's version (part of the cache key).
pub const VERSION: &str = "sandblaster-lift-conformance/6";
/// The buffer model in Rust (the harness's crate `bytes`).
pub const BYTES_SHIM: &str = include_str!("../lift/conform_bytes.rs");
/// The host traits the lift knows (the harness root).
pub const HOST_SHIM: &str = include_str!("../lift/conform_host.rs");
const SEED: u64 = 0x5eed_c0f0_2026_0929;
/// Candidate inputs per function before mutation.
const INITIAL: usize = 160;
/// Kernel evaluations per function (candidates and mutants).
const EVALS: usize = 400;
/// Rounds over the functions (states found in one round are inputs of the next).
const ROUNDS: usize = 4;
/// Kernel steps per evaluation.
const STEPS: u64 = 500_000_000;
/// The largest input (scalar elements, [`Gen::elems`]) the check builds:
/// a larger one (a 65,536-entry table of an engine) is skipped, named.
const MAX_INPUT_ELEMS: u64 = 1 << 16;
/// Wall-clock limit of the harness run.
const RUN_TIMEOUT: Duration = Duration::from_secs(120);
/// The harness module appended to the source copy.
const HARNESS_MOD: &str = "__sandblaster_conformance";
/// Inputs sought inside each panic contract's panic region (in place):
/// generated on purpose, after the coverage-driven inputs, until this many
/// are found or [`PANIC_TRIES`] candidates are spent.
const PANIC_INPUTS: usize = 16;
/// Candidates tried per panic contract in that search (only its domain and
/// precondition checkers are evaluated on them).
const PANIC_TRIES: usize = 4096;
/// Why a function returning `impl Trait` without a panic contract is not
/// called by the harness.
const OPAQUE_SKIP: &str = "it returns `impl Trait` (an opaque value the harness cannot compare: compared through its callers)";

/// Where and with what the check runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The `rustc` that compiles the original (the build's `RUSTC`).
    pub rustc: PathBuf,
    /// A directory the check owns (harness sources, binary, cache key).
    pub work_dir: PathBuf,
    /// The host crate's edition.
    pub edition: String,
    /// The verifier context (`driver::cache::verifier_context`: the
    /// toolchain's content hash, never the build script's): part of the key.
    pub toolchain_id: String,
    /// The host crate's directory (its `Cargo.toml` and `src/`): the
    /// harness of in-place modules is a copy of the host crate
    /// ([`check_in_place`]); `None` outside a build.
    pub manifest_dir: Option<PathBuf>,
    /// The `cargo` that builds that copy (the build's `CARGO`, else `cargo`).
    pub cargo: PathBuf,
    /// The host crate's features the build enabled (`CARGO_FEATURE_*`
    /// names: upper case, `_` for `-`); `None` or none enabled: the
    /// default features.
    pub features: Option<Vec<String>>,
    /// The build's environment variables that change how cargo builds the
    /// in-place harness (`in_place::affects_cargo`; the copy inherits them):
    /// part of its key. Empty outside a build.
    pub build_env: Vec<(String, String)>,
}

impl Config {
    /// A configuration outside a build (no host crate: in-place modules
    /// cannot be checked).
    pub fn new(rustc: PathBuf, work_dir: PathBuf, edition: &str, toolchain_id: &str) -> Config {
        Config { rustc, work_dir, edition: edition.into(), toolchain_id: toolchain_id.into(), manifest_dir: None, cargo: PathBuf::from("cargo"), features: None, build_env: Vec::new() }
    }

    /// The configuration of a module-mode build: `RUSTC` (else `rustc`),
    /// `OUT_DIR/<out>-conformance/`, the edition of the host manifest (a
    /// workspace-inherited edition is read from the workspace manifest;
    /// `2021` when none is found) and the verdict context.
    pub fn for_build(env: &dyn Fn(&str) -> Option<String>, fs: &dyn crate::loader::FileProvider, manifest_dir: &Path, out_dir: &Path, out: &str, context: Option<&str>) -> Config {
        Config {
            rustc: PathBuf::from(env("RUSTC").unwrap_or_else(|| "rustc".into())),
            work_dir: out_dir.join(format!("{out}-conformance")),
            edition: edition_of(fs, manifest_dir).unwrap_or_else(|| "2021".into()),
            toolchain_id: context.unwrap_or("").to_string(),
            manifest_dir: Some(manifest_dir.to_path_buf()),
            cargo: PathBuf::from(env("CARGO").unwrap_or_else(|| "cargo".into())),
            features: Some(std::env::vars().filter_map(|(k, _)| k.strip_prefix("CARGO_FEATURE_").map(str::to_string)).collect()),
            build_env: std::env::vars().filter(|(k, _)| in_place::affects_cargo(k)).collect(),
        }
    }
}

/// The `edition` of the manifest in `dir` (following `edition.workspace =
/// true` to the nearest ancestor manifest with a `[workspace.package]`
/// edition).
pub fn edition_of(fs: &dyn crate::loader::FileProvider, dir: &Path) -> Option<String> {
    let text = fs.read(&dir.join("Cargo.toml")).ok()?;
    let own = manifest_value(&text, "package", "edition");
    match own.as_deref() {
        Some(e) if !e.contains("workspace") => return Some(e.to_string()),
        Some(_) => {}
        None => return None,
    }
    let mut d = dir.parent();
    while let Some(p) = d {
        if let Ok(t) = fs.read(&p.join("Cargo.toml"))
            && let Some(e) = manifest_value(&t, "workspace.package", "edition")
        {
            return Some(e);
        }
        d = p.parent();
    }
    None
}

/// `key = "value"` (or `key.workspace = true`, returned as `workspace`) in
/// table `[table]` of a manifest (a line scan: enough for `edition`).
fn manifest_value(text: &str, table: &str, key: &str) -> Option<String> {
    let mut cur = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            cur = l.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            continue;
        }
        if cur != table {
            continue;
        }
        if let Some(rest) = l.strip_prefix(key) {
            let rest = rest.trim_start();
            if rest.starts_with(".workspace") || rest.contains("workspace") {
                return Some("workspace".into());
            }
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

/// One function's part of the check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryReport {
    pub lifted: String,
    /// The original, as the harness calls it.
    pub callee: String,
    /// Inputs compared.
    pub cases: usize,
    /// Distinct outcome classes seen.
    pub classes: usize,
    /// Candidates the kernel rejected (a struct invariant does not hold).
    pub rejected: usize,
    /// Evaluations by the reference strategy (arguments with erased proofs).
    pub reference: usize,
    /// Why the function was not checked (it is reached through its callers).
    pub skipped: Option<String>,
    /// Inputs on which the literal reading L of its MIR was compared with
    /// rustc's build too ([`literal`]).
    pub literal: usize,
    /// Inputs of its panic contract's panic region on which rustc panicked
    /// and L gave `Panic` (in place; part of `literal`).
    pub panics: usize,
}

/// A difference between the lifted model and `rustc`'s build.
#[derive(Clone, Debug)]
pub struct Mismatch {
    pub lifted: String,
    pub callee: String,
    pub input: String,
    pub model: String,
    pub rustc: String,
}

/// The check's result.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// A pass recorded under the same key was reused.
    pub cached: bool,
    pub key: String,
    /// `rustc -vV`'s release line.
    pub rustc: String,
    pub edition: String,
    pub entries: Vec<EntryReport>,
    pub mismatches: Vec<Mismatch>,
    /// Failures of the check itself (the harness does not compile, `rustc`
    /// cannot run, ...): each fails the build.
    pub errors: Vec<String>,
    pub notes: Vec<String>,
    pub cases: usize,
    /// Inputs on which the literal reading L was compared with rustc.
    pub literal_cases: usize,
    pub elapsed: Duration,
}

impl Report {
    /// Adds the report of another lifted module (a crate verified in
    /// place checks each of its in-place modules): one report whose key
    /// covers both.
    pub fn absorb(&mut self, o: Report) {
        self.key = if self.key.is_empty() { o.key } else { hex(&sha256(format!("{}\n{}", self.key, o.key).as_bytes())) };
        self.cached = if self.entries.is_empty() && self.errors.is_empty() && self.cases == 0 { o.cached } else { self.cached && o.cached };
        if self.rustc.is_empty() {
            self.rustc = o.rustc;
        }
        if self.edition.is_empty() {
            self.edition = o.edition;
        }
        self.entries.extend(o.entries);
        self.mismatches.extend(o.mismatches);
        self.errors.extend(o.errors);
        self.notes.extend(o.notes);
        self.cases += o.cases;
        self.literal_cases += o.literal_cases;
        self.elapsed += o.elapsed;
    }

    /// No mismatch and no failure of the check.
    pub fn passed(&self) -> bool {
        self.mismatches.is_empty() && self.errors.is_empty()
    }

    /// One line for the build summary (deterministic: no time, and the
    /// same whether the check ran or its recorded pass was replayed).
    pub fn summary(&self) -> String {
        let checked = self.entries.iter().filter(|e| e.skipped.is_none()).count();
        let lit_fns = self.entries.iter().filter(|e| e.literal > 0).count();
        format!("lift conformance: {} input(s) on {checked} function(s) ({} skipped), the literal reading of the MIR on {} input(s) of {lit_fns} function(s), {} mismatch(es), rustc {} edition {}", self.cases, self.entries.len() - checked, self.literal_cases, self.mismatches.len(), self.rustc, self.edition)
    }

    /// The line the emitted module's header carries (deterministic: the
    /// same inputs give the same line, cached or not).
    pub fn header_line(&self) -> String {
        format!("lift conformance passed (key {})", &self.key[..16.min(self.key.len())])
    }

    /// The failure messages (the build's error lines).
    pub fn failures(&self) -> Vec<String> {
        let mut v: Vec<String> = self.errors.iter().map(|e| format!("lift conformance: {e}")).collect();
        for m in self.mismatches.iter().take(20) {
            v.push(format!("lift conformance: `{}` (the original `{}`) differs from rustc's build on input {}: the lifted model gives {}, rustc's build gives {}", m.lifted, m.callee, m.input, m.model, m.rustc));
        }
        if self.mismatches.len() > 20 {
            v.push(format!("lift conformance: … {} more mismatch(es)", self.mismatches.len() - 20));
        }
        v
    }

    /// The report section (deterministic: no times).
    pub fn json(&self) -> Json {
        let mut j = Json::obj();
        j.bool("passed", self.passed());
        j.str("key", &self.key);
        j.str("rustc", &self.rustc);
        j.str("edition", &self.edition);
        j.num("cases", self.cases as i64);
        j.num("literal_cases", self.literal_cases as i64);
        j.put(
            "functions",
            Json::Arr(
                self.entries
                    .iter()
                    .map(|e| {
                        let mut o = Json::obj();
                        o.str("lifted", &e.lifted);
                        o.str("original", &e.callee);
                        o.num("cases", e.cases as i64);
                        o.num("outcome_classes", e.classes as i64);
                        o.num("rejected_by_invariant", e.rejected as i64);
                        o.num("reference_evaluations", e.reference as i64);
                        o.num("literal_cases", e.literal as i64);
                        if e.panics > 0 {
                            o.num("panic_cases", e.panics as i64);
                        }
                        if let Some(s) = &e.skipped {
                            o.str("skipped", s);
                        }
                        o
                    })
                    .collect(),
            ),
        );
        j.put("failures", Json::Arr(self.failures().iter().map(|f| Json::string(f)).collect()));
        j.put("notes", Json::Arr(self.notes.iter().map(|f| Json::string(f)).collect()));
        j
    }
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

/// Runs the check for the lifted module `info` of the checked crate `c`
/// on its elaboration `out` (every definition kernel-checked).
pub fn check(out: &mut elab::Output, krate: &Crate, c: &Checked, info: &LiftedInfo, cfg: &Config) -> Report {
    let t0 = Instant::now();
    let mut rep = Report { edition: cfg.edition.clone(), ..Default::default() };
    if let Some(h) = c.lift_facts.test_hook {
        rep.notes.push(format!("the lift ran with the test hook `{h:?}` (a deliberately wrong rule)"));
    }
    let Some(src) = c.sm.get(info.file).map(|f| f.text.clone()) else {
        rep.errors.push(format!("the source of `{}` is not in the source map", info.name));
        return rep;
    };
    if src.contains(HARNESS_MOD) {
        rep.errors.push(format!("the source mentions `{HARNESS_MOD}`, the harness module's name"));
        return rep;
    }
    let hosts: Vec<(String, String)> = c.lifted.iter().filter(|l| l.host).map(|l| (l.name.clone(), c.sm.get(l.file).map(|f| f.text.clone()).unwrap_or_default())).collect();
    let entries: Vec<&ConformEntry> = c.lift_facts.conform.iter().filter(|e| e.module == info.name && !e.opaque_ret).collect();
    // lifted functions without an entry of their own (loop helpers, ..),
    // and those returning `impl Trait` (compared only in place, on a panic
    // contract's panic region): reported, compared through their callers
    for sk in c.lift_facts.conform_skipped.iter().filter(|s| s.module == info.name) {
        rep.entries.push(EntryReport { lifted: sk.lifted.clone(), callee: "(none)".into(), skipped: Some(sk.why.clone()), ..Default::default() });
    }
    for e in c.lift_facts.conform.iter().filter(|e| e.module == info.name && e.opaque_ret) {
        rep.entries.push(EntryReport { lifted: e.lifted.clone(), callee: "(none)".into(), skipped: Some(OPAQUE_SKIP.into()), ..Default::default() });
    }
    // what the harness cannot build yet fails the check (never a vacuous pass)
    if info.in_place {
        rep.errors.push(format!("`{}` is lifted in place: the harness compiles one lifted file on its own, and an in-place file is part of its host crate (it names the crate's other modules and dependencies); an in-place crate is checked as a whole by `check_in_place` (a copy of the host crate), so no verdict is issued here", info.name));
        rep.elapsed = t0.elapsed();
        return rep;
    }
    if !c.lift_facts.open_instances.is_empty() {
        let list: Vec<String> = c.lift_facts.open_instances.iter().map(|(t, p)| format!("`{t}` at `{p}`")).collect();
        rep.errors.push(format!("the crate lifts open traits at declared instances ({}): the harness cannot yet spell the source's generic items at their instance, so no verdict is issued", list.join(", ")));
        rep.elapsed = t0.elapsed();
        return rep;
    }
    // rustc
    let rv = match Command::new(&cfg.rustc).arg("-vV").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        Ok(o) => {
            rep.errors.push(format!("`{} -vV` failed: {}", cfg.rustc.display(), String::from_utf8_lossy(&o.stderr).trim()));
            return rep;
        }
        Err(e) => {
            rep.errors.push(format!("cannot run `{}`: {e}", cfg.rustc.display()));
            return rep;
        }
    };
    rep.rustc = rv.lines().find_map(|l| l.strip_prefix("release: ")).unwrap_or("?").to_string();
    // the cache key
    let mut k = format!("{VERSION}\ntoolchain {}\nedition {}\nrustc {}\n", hex(&sha256(cfg.toolchain_id.as_bytes())), cfg.edition, hex(&sha256(rv.as_bytes())));
    k.push_str(&format!("source {} {}\n", info.name, hex(&sha256(src.as_bytes()))));
    for (n, t) in &hosts {
        k.push_str(&format!("host {n} {}\n", hex(&sha256(t.as_bytes()))));
    }
    k.push_str(&format!("shims {} {}\n", hex(&sha256(BYTES_SHIM.as_bytes())), hex(&sha256(HOST_SHIM.as_bytes()))));
    k.push_str(&format!("entries {}\n", hex(&sha256(format!("{entries:?}{:?}{:?}", c.lift_facts.instances, c.lift_facts.test_hook).as_bytes()))));
    k.push_str(&format!("budget {INITIAL} {EVALS} {ROUNDS} {STEPS} {SEED} {LITERAL_CASES}\n"));
    k.push_str(&literal_key(c));
    k.push_str(&items_key(krate));
    rep.key = hex(&sha256(k.as_bytes()));
    let key_path = cfg.work_dir.join("conformance.key");
    if let Some(r) = recorded_pass(c, &key_path, &rep.key) {
        r.replay(&mut rep);
        rep.cached = true;
        rep.elapsed = t0.elapsed();
        return rep;
    }
    let _ = std::fs::remove_file(&key_path);
    if let Err(e) = std::fs::create_dir_all(&cfg.work_dir) {
        rep.errors.push(format!("cannot create `{}`: {e}", cfg.work_dir.display()));
        return rep;
    }
    // the literal reading of every function read from MIR (amendment (f))
    let lits = literal::prepare(out, c, &entries, &mut rep);
    let mut g = Gen::new(out, krate, c, info);
    let plans = g.plans(&entries, &mut rep);
    let cases = g.run(&plans, &mut rep);
    rep.cases = cases.len();
    if rep.errors.is_empty() {
        match harness(&g, &plans, &cases, &src, &hosts, cfg) {
            Ok(outputs) => {
                let rustc = compare(&g, &plans, &cases, &outputs, &mut rep);
                let panics = literal::compare(&g, &plans, &cases, &rustc, &lits, &mut rep);
                panic_coverage(krate, &entries, &panics, &mut rep);
            }
            Err(e) => rep.errors.push(e),
        }
    }
    rep.elapsed = t0.elapsed();
    if rep.passed() {
        record_pass(c, &key_path, &rep);
    }
    rep
}

/// The shared verdict cache's namespace of passes of this check
/// (`driver::cache`): an entry is a [`Record`] under the check's key.
pub const CACHE_NS: &str = "conformance";

/// A recorded pass under `key`: the work directory's record, else the
/// shared verdict cache's entry (the build's, `Checked::cache`; a new target
/// directory reuses the pass of another one). An entry of another key, a
/// malformed record or an entry that fails its integrity check is a miss.
pub(crate) fn recorded_pass(c: &Checked, key_path: &Path, key: &str) -> Option<Record> {
    if let Some(r) = std::fs::read_to_string(key_path).ok().and_then(|t| Record::parse(&t, key)) {
        return Some(r);
    }
    let vc = c.cache.as_deref()?;
    match vc.store.get(CACHE_NS, key) {
        crate::driver::cache::Lookup::Hit(files) => files.iter().find(|(n, _)| n == "record").and_then(|(_, t)| Record::parse(t, key)),
        _ => None,
    }
}

/// Records a pass: in the work directory and in the shared verdict cache
/// (a failure to write either only costs a re-run).
pub(crate) fn record_pass(c: &Checked, key_path: &Path, rep: &Report) {
    let text = Record::of(rep).render();
    let _ = std::fs::write(key_path, &text);
    if let Some(vc) = c.cache.as_deref() {
        let _ = vc.store.put(CACHE_NS, &rep.key, &[("record", text.as_str())]);
    }
}

/// The part of the cache key that the DSL crate adds (both modes): a
/// position-independent fingerprint ([`crate::mutate::cache::Fps`]) of
/// every item but laws, lemmas and proofs. The check reads the lifted
/// functions and the host models, the constants the input pools draw from,
/// the types whose invariants filter inputs, and the spec functions the
/// precondition checkers call (which may live in any file of the DSL
/// crate); it never reads a law, a lemma or a proof, so editing one, or
/// moving code, leaves the key unchanged.
pub fn items_key(krate: &Crate) -> String {
    let fps = crate::mutate::cache::Fps::new(krate);
    let mut lines: Vec<String> = krate
        .items
        .iter()
        .filter(|it| !matches!(&it.kind, ItemKind::Fn(f) if matches!(f.kind, FnKind::Law | FnKind::Lemma | FnKind::Proof)))
        .map(|it| format!("{} {}", it.path, fps.item(it.id)))
        .collect();
    lines.sort();
    format!("items {}\n", hex(&sha256(lines.join("\n").as_bytes())))
}

/// A recorded pass (`conformance.key` in the work directory): the key and
/// the deterministic part of the report, replayed on a cache hit so that
/// the report does not depend on whether the check ran.
#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub key: String,
    pub rustc: String,
    pub cases: usize,
    pub literal_cases: usize,
    pub notes: Vec<String>,
    pub entries: Vec<EntryReport>,
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n").replace('\t', "\\t")
}

fn unesc(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(o) => out.push(o),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl Record {
    /// The record of a passing report.
    pub fn of(r: &Report) -> Record {
        Record { key: r.key.clone(), rustc: r.rustc.clone(), cases: r.cases, literal_cases: r.literal_cases, notes: r.notes.clone(), entries: r.entries.clone() }
    }

    /// The file text: the version and the key first (a record of another
    /// version or key is a miss), then one line per field.
    pub fn render(&self) -> String {
        let mut t = format!("{VERSION}\npassed {}\nrustc {}\ncases {}\nliteral {}\n", self.key, esc(&self.rustc), self.cases, self.literal_cases);
        for n in &self.notes {
            t.push_str(&format!("note {}\n", esc(n)));
        }
        for e in &self.entries {
            t.push_str(&format!("entry {}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n", esc(&e.lifted), esc(&e.callee), e.cases, e.classes, e.rejected, e.reference, e.literal, e.panics, e.skipped.as_deref().map(|s| format!("+{}", esc(s))).unwrap_or_else(|| "-".into())));
        }
        t
    }

    /// The record of `key` in `text`; `None` (a miss: the check runs) for
    /// another version or key or a malformed record.
    pub fn parse(text: &str, key: &str) -> Option<Record> {
        let mut lines = text.lines();
        if lines.next()? != VERSION || lines.next()? != format!("passed {key}") {
            return None;
        }
        let rustc = unesc(lines.next()?.strip_prefix("rustc ")?);
        let cases = lines.next()?.strip_prefix("cases ")?.parse().ok()?;
        let literal_cases = lines.next()?.strip_prefix("literal ")?.parse().ok()?;
        let mut r = Record { key: key.to_string(), rustc, cases, literal_cases, notes: Vec::new(), entries: Vec::new() };
        for l in lines {
            if let Some(n) = l.strip_prefix("note ") {
                r.notes.push(unesc(n));
            } else {
                let f: Vec<&str> = l.strip_prefix("entry ")?.split('\t').collect();
                let [lifted, callee, cases, classes, rejected, reference, literal, panics, skipped]: [&str; 9] = f.try_into().ok()?;
                let skipped = match skipped {
                    "-" => None,
                    s => Some(unesc(s.strip_prefix('+')?)),
                };
                r.entries.push(EntryReport { lifted: unesc(lifted), callee: unesc(callee), cases: cases.parse().ok()?, classes: classes.parse().ok()?, rejected: rejected.parse().ok()?, reference: reference.parse().ok()?, literal: literal.parse().ok()?, panics: panics.parse().ok()?, skipped });
            }
        }
        Some(r)
    }

    /// Fills a report with the recorded pass.
    pub fn replay(self, rep: &mut Report) {
        rep.rustc = self.rustc;
        rep.cases = self.cases;
        rep.literal_cases = self.literal_cases;
        rep.notes = self.notes;
        rep.entries = self.entries;
    }
}

// ---------------------------------------------------------------------------
// plans, inputs and kernel evaluation
// ---------------------------------------------------------------------------

/// A function to check.
struct Plan<'a> {
    e: &'a ConformEntry,
    index: usize,
    g: GlobalId,
    params: Vec<Ty>,
    ret: Ty,
    /// The output components: the states, then the result.
    comps: Vec<Ty>,
    /// Index of the parameter each state component comes from.
    state_of: Vec<usize>,
    callee: String,
    invariant_arg: bool,
    /// The checker of the function's precondition (in-place modules).
    pre: Option<GlobalId>,
    /// A panic contract (`panics_when(p)`, in-place modules): the checker of
    /// its domain, the `requires` before the no-panic clause (`None`: every
    /// input). An input in the domain that does not meet the precondition
    /// meets `p`: rustc must panic on it, and the literal reading too
    /// ([`PANIC_CASE`]).
    pre_dom: Option<Option<GlobalId>>,
    /// The original returns `impl Trait` (`ConformEntry::opaque_ret`): only
    /// inputs of its panic region are compared (no result is read back).
    panic_only: bool,
}

/// The model's outcome of an input on which the function's panic contract
/// says it panics (a [`Case`]'s `model`): the structured reading is not
/// evaluated there; rustc must panic, and the literal reading must give
/// `Panic` (`literal::compare`).
pub(super) const PANIC_CASE: &str = "a panic (its panic contract's condition holds)";

/// One compared input.
struct Case {
    plan: usize,
    args: Vec<J>,
    model: Result<Vec<J>, String>,
}

struct Gen<'a> {
    out: &'a elab::Output,
    krate: &'a Crate,
    c: &'a Checked,
    module: String,
    hosts: Vec<String>,
    /// Harvested values by type key (structs of the lifted module).
    harvest: HashMap<String, Vec<J>>,
    /// How many harvested values of each (type, shape) are kept.
    harvest_shapes: HashMap<(String, String), usize>,
    pools: HashMap<String, Vec<J>>,
    rng: Rng,
    /// In-place modules: how the harness (a copy of the host crate)
    /// spells the source's items ([`in_place`]).
    ip: Option<in_place::Spell>,
    /// In-place modules: the checkers of the functions' preconditions
    /// (lifted function → its checker in `pre_out`'s environment), so that
    /// a function with a `requires` is compared on the inputs that meet it.
    pre: HashMap<ItemId, GlobalId>,
    /// In-place modules: the functions with a panic contract, each with the
    /// checker of its domain (`None`: every input), so that the inputs where
    /// it panics are compared too (rustc panics, the literal reading panics).
    pre_dom: HashMap<ItemId, Option<GlobalId>>,
    pre_out: Option<&'a elab::Output>,
}

/// A `core::arch` vector as the array of its lanes, lane 0 first (its
/// kernel value; the harness transmutes between the two, which is the
/// lanes' memory order on the little-endian targets).
fn lanes_ty(t: &Ty) -> Option<Ty> {
    match t.peel_refs() {
        Ty::Vector(v) => {
            let (lane, n) = v.lanes();
            Some(Ty::Array(Box::new(Ty::Uint(lane)), n))
        }
        _ => None,
    }
}

fn tkey(t: &Ty) -> String {
    format!("{t:?}")
}

fn num(j: &J) -> Option<u128> {
    match j {
        J::Num(s) => s.parse().ok(),
        _ => None,
    }
}

impl<'a> Gen<'a> {
    fn new(out: &'a elab::Output, krate: &'a Crate, c: &'a Checked, info: &LiftedInfo) -> Gen<'a> {
        Gen { out, krate, c, module: info.name.clone(), hosts: c.lifted.iter().filter(|l| l.host).map(|l| l.name.clone()).collect(), harvest: HashMap::new(), harvest_shapes: HashMap::new(), pools: HashMap::new(), rng: Rng(SEED), ip: None, pre: HashMap::new(), pre_dom: HashMap::new(), pre_out: None }
    }

    fn conv(&self) -> Conv<'_> {
        Conv { env: &self.out.env, krate: self.krate, adts: &self.out.adts }
    }

    fn plans<'e>(&mut self, entries: &[&'e ConformEntry], rep: &mut Report) -> Vec<Plan<'e>> {
        let mut plans = Vec::new();
        for e in entries {
            let mut er = EntryReport { lifted: e.lifted.clone(), ..Default::default() };
            let skip = |er: &mut EntryReport, why: String, rep: &mut Report| {
                er.skipped = Some(why);
                rep.entries.push(er.clone());
            };
            let callee = match self.ip_callee(e).unwrap_or_else(|| self.callee(&e.callee)) {
                Ok(c) => c,
                Err(why) => {
                    er.callee = format!("{:?}", e.callee);
                    skip(&mut er, why, rep);
                    continue;
                }
            };
            er.callee = callee.clone();
            let Some(id) = self.krate.find(&e.lifted) else {
                rep.errors.push(format!("the lifted function `{}` is not in the crate", e.lifted));
                continue;
            };
            let Some(f) = self.krate.fn_def(id) else { continue };
            let Some(&g) = self.out.fn_globals.get(&id) else {
                rep.errors.push(format!("`{}` was not elaborated", e.lifted));
                continue;
            };
            let pre = self.pre.get(&id).copied();
            let pre_dom = self.pre_dom.get(&id).copied();
            // (an opaque result: compared only where it panics)
            if e.opaque_ret && (pre.is_none() || pre_dom.is_none()) {
                skip(&mut er, OPAQUE_SKIP.into(), rep);
                continue;
            }
            if f.params.iter().any(|p| p.ghost) || (pre.is_none() && self.out.env.global_param_rels(g).is_none_or(|r| r.contains(&Rel::Irr))) {
                skip(&mut er, "it has a precondition (it is checked through its callers)".into(), rep);
                continue;
            }
            if f.params.len() != e.params.len() {
                rep.errors.push(format!("`{}`: the lift recorded {} parameter(s), the lifted function has {}", e.lifted, e.params.len(), f.params.len()));
                continue;
            }
            let params: Vec<Ty> = f.params.iter().map(|p| p.ty.clone()).collect();
            let mut comps = Vec::new();
            let mut state_of = Vec::new();
            for (i, (p, t)) in e.params.iter().zip(&params).enumerate() {
                match p {
                    ParamPass::MutRef | ParamPass::Buf | ParamPass::BufMut => {
                        comps.push(t.peel_refs().clone());
                        state_of.push(i);
                    }
                    // (the lifted parameter is the state's value)
                    ParamPass::StateMut | ParamPass::VecMut | ParamPass::OptVec | ParamPass::BytesIter => {
                        comps.push(t.clone());
                        state_of.push(i);
                    }
                    _ => {}
                }
            }
            if e.has_ret && !e.opaque_ret {
                let r = match (&f.ret, comps.len()) {
                    (Ty::Tuple(ts), n) if n > 0 && ts.len() == n + 1 => ts[n].clone(),
                    (t, 0) => t.clone(),
                    (t, _) => {
                        rep.errors.push(format!("`{}`: unexpected lifted return type {t:?}", e.lifted));
                        continue;
                    }
                };
                comps.push(r);
            }
            let unsupported = params.iter().chain(comps.iter()).find_map(|t| self.rust_ty(t).err());
            if let Some(why) = unsupported {
                skip(&mut er, why, rep);
                continue;
            }
            // (an input of more than `MAX_INPUT_ELEMS` elements: each kernel
            // evaluation would build it whole, beyond the per-function budget)
            if let Some(n) = params.iter().map(|t| self.elems(t)).find(|n| *n > MAX_INPUT_ELEMS) {
                skip(&mut er, format!("an input holds {n} elements (a table of the engine, fixed in its type): beyond the check's evaluation budget ({MAX_INPUT_ELEMS})"), rep);
                continue;
            }
            let invariant_arg = params.iter().any(|t| self.has_invariant(t));
            rep.entries.push(er);
            plans.push(Plan { e, index: rep.entries.len() - 1, g, params, ret: f.ret.clone(), comps, state_of, callee, invariant_arg, pre, pre_dom, panic_only: e.opaque_ret });
        }
        plans
    }

    /// The number of scalar elements a value of `t` holds (arrays multiplied
    /// out, a sequence or slice counted as one element: its length is the
    /// generator's), saturating.
    fn elems(&self, t: &Ty) -> u64 {
        self.elems_at(t, 0)
    }

    fn elems_at(&self, t: &Ty, depth: u32) -> u64 {
        if depth > 16 {
            return 1;
        }
        match t.peel_refs() {
            Ty::Array(e, n) => (*n).saturating_mul(self.elems_at(e, depth + 1)),
            Ty::Tuple(ts) => ts.iter().map(|x| self.elems_at(x, depth + 1)).fold(0u64, u64::saturating_add).max(1),
            Ty::Adt(id, args) => match self.fields_of(*id, args) {
                Some((_, fs)) => fs.iter().map(|(_, x)| self.elems_at(x, depth + 1)).fold(0u64, u64::saturating_add).max(1),
                None => 1,
            },
            _ => 1,
        }
    }

    fn has_invariant(&self, t: &Ty) -> bool {
        match t.peel_refs() {
            Ty::Adt(id, _) => matches!(&self.krate.item(*id).kind, ItemKind::Struct(s) if s.invariant.is_some()),
            Ty::Tuple(ts) => ts.iter().any(|x| self.has_invariant(x)),
            _ => false,
        }
    }

    // -- Rust spellings ------------------------------------------------------

    /// A type as the source writes it (`u16`, `Foo`), qualified for the
    /// harness module: primitives as they are, anything else under `super::`.
    fn qualify_src_ty(&self, s: &str) -> String {
        let t: syn::Type = match syn::parse_str(s) {
            Ok(t) => t,
            Err(_) => return s.to_string(),
        };
        struct Q;
        impl syn::visit_mut::VisitMut for Q {
            fn visit_type_path_mut(&mut self, p: &mut syn::TypePath) {
                syn::visit_mut::visit_type_path_mut(self, p);
                if p.qself.is_none() && p.path.leading_colon.is_none() {
                    let first = p.path.segments[0].ident.to_string();
                    let prim = matches!(first.as_str(), "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "bool" | "crate" | "Self" | "super" | "self");
                    if !prim {
                        p.path.segments.insert(0, syn::parse_quote!(super));
                    }
                }
            }
        }
        let mut t = t;
        syn::visit_mut::VisitMut::visit_type_mut(&mut Q, &mut t);
        quote::ToTokens::to_token_stream(&t).to_string()
    }

    /// A path as an impl writes it in the inline module `modpath`,
    /// qualified for the harness module (`Default`/`From<..>` are core's).
    fn qualify_trait(&self, written: &str, modpath: &[String]) -> Result<String, String> {
        let p: syn::Path = syn::parse_str(written).map_err(|e| format!("cannot read the trait path `{written}`: {e}"))?;
        let first = p.segments[0].ident.to_string();
        let args = |seg: &syn::PathSegment| -> String {
            match &seg.arguments {
                syn::PathArguments::AngleBracketed(a) => {
                    let xs: Vec<String> = a.args.iter().map(|x| match x {
                        syn::GenericArgument::Type(t) => self.qualify_src_ty(&quote::ToTokens::to_token_stream(t).to_string()),
                        other => quote::ToTokens::to_token_stream(other).to_string(),
                    }).collect();
                    format!("<{}>", xs.join(", "))
                }
                _ => String::new(),
            }
        };
        if p.segments.len() == 1 && first == "Default" {
            return Ok("::core::default::Default".into());
        }
        if p.segments.len() == 1 && first == "From" {
            return Ok(format!("::core::convert::From{}", args(&p.segments[0])));
        }
        // the core traits the lift reads by name (operators, comparisons,
        // conversions, `Deref`, `Iterator`: `crate::lift::open`)
        if p.segments.len() == 1 {
            let module = match first.as_str() {
                "Add" | "Sub" | "Mul" | "Div" | "Rem" | "BitAnd" | "BitOr" | "BitXor" | "Shl" | "Shr" | "AddAssign" | "SubAssign" | "MulAssign" | "DivAssign" | "RemAssign" | "BitAndAssign" | "BitOrAssign" | "BitXorAssign" | "ShlAssign" | "ShrAssign" | "Deref" => Some("ops"),
                "PartialEq" | "PartialOrd" | "Ord" => Some("cmp"),
                "TryFrom" | "AsRef" => Some("convert"),
                "Iterator" => Some("iter"),
                _ => None,
            };
            if let Some(m) = module {
                return Ok(format!("::core::{m}::{first}{}", args(&p.segments[0])));
            }
        }
        if matches!(first.as_str(), "core" | "std" | "alloc") {
            return Ok(format!("::{}", quote::ToTokens::to_token_stream(&p).to_string().replace(' ', "")));
        }
        if p.leading_colon.is_some() || first == "crate" {
            return Ok(written.to_string());
        }
        let mut s = String::from("super::");
        for m in modpath {
            s.push_str(m);
            s.push_str("::");
        }
        let segs: Vec<String> = p.segments.iter().map(|seg| format!("{}{}", seg.ident, args(seg))).collect();
        s.push_str(&segs.join("::"));
        Ok(s)
    }

    /// The harness's expression for the original function.
    fn callee(&self, c: &ConformCallee) -> Result<String, String> {
        let turbofish = |g: &[String]| if g.is_empty() { String::new() } else { format!("::<{}>", g.iter().map(|x| self.qualify_src_ty(x)).collect::<Vec<_>>().join(", ")) };
        Ok(match c {
            ConformCallee::Free { modpath, name, generics } => {
                if !modpath.is_empty() {
                    return Err(format!("the function is in the inline module `{}` (not visible to the harness; it is checked through its callers)", modpath.join("::")));
                }
                format!("super::{name}{}", turbofish(generics))
            }
            ConformCallee::Inherent { base, generics, method, .. } => format!("super::{base}{}::{method}", turbofish(generics)),
            ConformCallee::Trait { modpath, self_ty, trait_path, method } => format!("<{} as {}>::{method}", self.qualify_src_ty(self_ty), self.qualify_trait(trait_path, modpath)?),
        })
    }

    /// The Rust type (in the harness module) of a lifted type, and the
    /// path used in expressions and patterns (turbofish form).
    fn adt_paths(&self, id: ItemId, args: &[Ty]) -> Result<(String, String), String> {
        if let Some(r) = self.ip_adt_paths(id, args) {
            return r;
        }
        let path = self.krate.item(id).path.to_string();
        let targs = args.iter().map(|a| self.rust_ty(a)).collect::<Result<Vec<_>, _>>()?;
        let generics = |ps: &[String]| if ps.is_empty() { (String::new(), String::new()) } else { (format!("<{}>", ps.join(", ")), format!("::<{}>", ps.join(", "))) };
        if path == "crate::__lift::Result" {
            let (a, b) = generics(&targs);
            return Ok((format!("::core::result::Result{a}"), format!("::core::result::Result{b}")));
        }
        if path == "crate::__lift::TryGetError" {
            return Ok(("::bytes::TryGetError".into(), "::bytes::TryGetError".into()));
        }
        let name = self.krate.item(id).name.clone();
        if path == format!("crate::{}::{name}", self.module) {
            if let Some((base, sargs)) = self.c.lift_facts.instances.get(&name) {
                let qs: Vec<String> = sargs.iter().map(|x| self.qualify_src_ty(x)).collect();
                let (a, b) = generics(&qs);
                return Ok((format!("super::{base}{a}"), format!("super::{base}{b}")));
            }
            let (a, b) = generics(&targs);
            return Ok((format!("super::{name}{a}"), format!("super::{name}{b}")));
        }
        for h in &self.hosts {
            if path == format!("crate::{h}::{name}") {
                let (a, b) = generics(&targs);
                return Ok((format!("crate::{h}::{name}{a}"), format!("crate::{h}::{name}{b}")));
            }
        }
        Err(format!("the type `{path}` has no Rust counterpart in the harness"))
    }

    fn signed_bits(&self, id: ItemId) -> Option<u32> {
        match self.krate.item(id).path.to_string().as_str() {
            "crate::__lift::I16" => Some(16),
            "crate::__lift::I32" => Some(32),
            "crate::__lift::I64" => Some(64),
            _ => None,
        }
    }

    fn rust_ty(&self, t: &Ty) -> Result<String, String> {
        Ok(match t {
            Ty::Vector(v) => v.path(),
            Ty::Bool => "bool".into(),
            Ty::Uint(u) => u.name().into(),
            Ty::Tuple(ts) if ts.is_empty() => "()".into(),
            Ty::Tuple(ts) => format!("({},)", ts.iter().map(|x| self.rust_ty(x)).collect::<Result<Vec<_>, _>>()?.join(", ")),
            Ty::Array(e, n) => format!("[{}; {n}]", self.rust_ty(e)?),
            Ty::Ref(x) => self.rust_ty(x)?,
            Ty::Option(e) => format!("::core::option::Option<{}>", self.rust_ty(e)?),
            Ty::Seq(e) | Ty::Slice(e) => format!("::std::vec::Vec<{}>", self.rust_ty(e)?),
            Ty::Adt(id, _) if self.signed_bits(*id).is_some() => format!("i{}", self.signed_bits(*id).unwrap_or(0)),
            Ty::Adt(id, args) => self.adt_paths(*id, args)?.0,
            other => return Err(format!("the type `{other:?}` has no Rust counterpart in the harness")),
        })
    }

    // -- candidate values ----------------------------------------------------

    fn val_j(&self, t: &Ty, v: &Val) -> Option<J> {
        if let Some(a) = lanes_ty(t) {
            return self.val_j(&a, v);
        }
        Some(match (t.peel_refs(), v) {
            (_, Val::Bool(b)) => J::Bool(*b),
            (_, Val::Int(n)) => J::Num(n.to_string()),
            (Ty::Tuple(ts), Val::Tuple(xs)) if ts.is_empty() && xs.is_empty() => J::Null,
            (Ty::Tuple(ts), Val::Tuple(xs)) => J::Arr(ts.iter().zip(xs).map(|(t, x)| self.val_j(t, x)).collect::<Option<_>>()?),
            (Ty::Array(e, _) | Ty::Seq(e) | Ty::Slice(e), Val::Seq(xs)) => J::Arr(xs.iter().map(|x| self.val_j(e, x)).collect::<Option<_>>()?),
            (Ty::Option(_), Val::Opt(None)) => J::Null,
            (Ty::Option(e), Val::Opt(Some(x))) => J::Obj(vec![("Some".into(), self.val_j(e, x)?)]),
            (Ty::Adt(id, args), Val::Adt { ctor, fields }) => match &self.krate.item(*id).kind {
                ItemKind::Struct(s) => self.fields_j(&s.fields, s.shape, args, fields)?,
                ItemKind::Enum(en) => {
                    let var = en.variants.get(*ctor as usize)?;
                    match var.shape {
                        Shape::Unit => J::Str(var.name.clone()),
                        _ => J::Obj(vec![(var.name.clone(), self.fields_j(&var.fields, var.shape, args, fields)?)]),
                    }
                }
                _ => return None,
            },
            _ => return None,
        })
    }

    fn fields_j(&self, defs: &[FieldDef], shape: Shape, args: &[Ty], vals: &[Val]) -> Option<J> {
        let js: Vec<J> = defs.iter().zip(vals).map(|(f, v)| self.val_j(&f.ty.subst(args), v)).collect::<Option<_>>()?;
        Some(match shape {
            Shape::Named => J::Obj(defs.iter().zip(js).map(|(f, j)| (f.name.clone().unwrap_or_default(), j)).collect()),
            Shape::Tuple => J::Arr(js),
            Shape::Unit => J::Null,
        })
    }

    fn fields_of(&self, id: ItemId, args: &[Ty]) -> Option<(Shape, Vec<(String, Ty)>)> {
        match &self.krate.item(id).kind {
            ItemKind::Struct(s) => Some((s.shape, s.fields.iter().map(|f| (f.name.clone().unwrap_or_default(), f.ty.subst(args))).collect())),
            _ => None,
        }
    }

    /// Candidate values of a parameter type (cached by type).
    fn pool(&mut self, t: &Ty, depth: u32) -> Vec<J> {
        if let Some(a) = lanes_ty(t) {
            return self.pool(&a, depth);
        }
        let t = t.peel_refs().clone();
        let k = tkey(&t);
        if let Some(p) = self.pools.get(&k) {
            let mut h = self.harvest.get(&k).cloned().unwrap_or_default();
            h.extend(p.iter().cloned());
            return dedup(h);
        }
        let mut hints = Hints { consts: Default::default(), rng: Rng(self.rng.next_u64()) };
        let mut out: Vec<J> = Vec::new();
        match &t {
            Ty::Uint(u) => {
                for v in meval::pool(self.krate, &t, &mut hints, 0) {
                    out.extend(self.val_j(&t, &v));
                }
                // every small value (counters, bit positions, lengths), then
                // the powers of two ±1
                out.extend((0u32..=64).map(|n| J::Num(n.to_string())));
                out.extend(boundary(u.bits()).into_iter().map(|n| J::Num(n.to_string())));
            }
            Ty::Adt(id, args) if depth < 3 && self.fields_of(*id, args).is_some() => {
                let (shape, fields) = self.fields_of(*id, args).unwrap_or((Shape::Unit, vec![]));
                let pools: Vec<Vec<J>> = fields.iter().map(|(_, ft)| self.pool(ft, depth + 1)).collect();
                for combo in combine(&pools, 96, &mut self.rng) {
                    out.push(match shape {
                        Shape::Named => J::Obj(fields.iter().map(|(n, _)| n.clone()).zip(combo).collect()),
                        Shape::Tuple => J::Arr(combo),
                        Shape::Unit => J::Null,
                    });
                }
            }
            _ => {
                for v in meval::pool(self.krate, &t, &mut hints, 0) {
                    out.extend(self.val_j(&t, &v));
                }
            }
        }
        let out = dedup(out);
        self.pools.insert(k.clone(), out.clone());
        let mut h = self.harvest.get(&k).cloned().unwrap_or_default();
        h.extend(out);
        dedup(h)
    }

    // -- kernel evaluation ---------------------------------------------------

    /// The lifted model on `args`: its output components, or `Err(None)`
    /// when an argument is not a value of its type (an invariant fails).
    fn eval(&self, p: &Plan<'_>, args: &[J], reference: &mut usize) -> Result<Vec<J>, Option<String>> {
        let conv = self.conv();
        let mut tms: Vec<(Rel, Tm)> = Vec::new();
        for (t, j) in p.params.iter().zip(args) {
            tms.push((Rel::Rel, conv.term(t, j).map_err(|_| None)?));
        }
        if let Some(chk) = p.pre {
            // the precondition, decided by its checker: an input that does
            // not meet it is not compared, unless it is in the domain of a
            // panic contract (then it meets the panic condition: compared as
            // a panic)
            if !self.meets_pre(chk, p, args).map_err(Some)? {
                return match p.pre_dom {
                    Some(dom) if dom.is_none_or(|d| self.meets_pre(d, p, args).unwrap_or(false)) => Err(Some(PANIC_CASE.into())),
                    _ => Err(None),
                };
            }
            // (the `requires` binders get erased proofs: the reference strategy)
            let rels = self.out.env.global_param_rels(p.g).unwrap_or_default();
            let mut it = tms.into_iter();
            let all: Vec<(Rel, Tm)> = rels.iter().map(|r| if *r == Rel::Irr { (Rel::Irr, std::rc::Rc::new(sandblaster_kernel::term::Term::Erased)) } else { it.next().unwrap_or((Rel::Rel, std::rc::Rc::new(sandblaster_kernel::term::Term::Erased))) }).collect();
            *reference += 1;
            let v = crate::driver::stage::eval_reference(&self.out.env, &mk::apps(mk::global(p.g), all), STEPS).map_err(Some)?;
            let r = conv.json(&p.ret, &v).map_err(Some)?;
            return Ok(if p.comps.len() == 1 {
                vec![r]
            } else {
                match r {
                    J::Arr(xs) if xs.len() == p.comps.len() => xs,
                    other => return Err(Some(format!("unexpected result shape {}", other.render()))),
                }
            });
        }
        let term = mk::apps(mk::global(p.g), tms);
        let v = if p.invariant_arg {
            *reference += 1;
            crate::driver::stage::eval_reference(&self.out.env, &term, STEPS).map_err(Some)?
        } else {
            let mut b = Budget { steps: STEPS };
            match self.out.env.eval_closed(&term, &mut b) {
                Ok(nf) => {
                    let mut b2 = Budget { steps: STEPS };
                    self.out.env.eval(&VEnv::default(), Lvl(0), &nf, &mut b2).map_err(|e| Some(format!("{e:?}")))?
                }
                Err(e) => return Err(Some(format!("eval_closed: {}", e.message.lines().next().unwrap_or("")))),
            }
        };
        let r = conv.json(&p.ret, &v).map_err(Some)?;
        Ok(if p.comps.len() == 1 {
            vec![r]
        } else {
            match r {
                J::Arr(xs) if xs.len() == p.comps.len() => xs,
                other => return Err(Some(format!("unexpected result shape {}", other.render()))),
            }
        })
    }

    /// Collects the struct values of an output (states reached).
    fn harvest_value(&mut self, t: &Ty, j: &J) {
        match (t.peel_refs(), j) {
            (Ty::Adt(id, args), _) if self.signed_bits(*id).is_none() => {
                if let Some((_, fields)) = self.fields_of(*id, args) {
                    if self.own_type(&self.krate.item(*id).path.to_string()) {
                        self.keep(t, j);
                    }
                    for (i, (n, ft)) in fields.iter().enumerate() {
                        let sub = match j {
                            J::Obj(kv) => kv.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()),
                            J::Arr(xs) => xs.get(i).cloned(),
                            _ => None,
                        };
                        if let Some(s) = sub {
                            self.harvest_value(ft, &s);
                        }
                    }
                } else if let (ItemKind::Enum(en), J::Obj(kv)) = (&self.krate.item(*id).kind, j)
                    && let Some((vn, payload)) = kv.first()
                    && let Some(var) = en.variants.iter().find(|v| &v.name == vn)
                    && let J::Arr(xs) = payload
                {
                    for (f, x) in var.fields.iter().zip(xs) {
                        self.harvest_value(&f.ty.subst(args), x);
                    }
                }
            }
            (Ty::Option(e), J::Obj(kv)) => {
                if let Some((_, x)) = kv.first() {
                    self.harvest_value(e, x);
                }
            }
            (Ty::Tuple(ts), J::Arr(xs)) => {
                for (t, x) in ts.iter().zip(xs) {
                    self.harvest_value(t, x);
                }
            }
            _ => {}
        }
    }

    /// Keeps a produced value as a candidate of its type: a few per length
    /// for a sequence, one per value with the integers above 64 replaced by
    /// their bit length for anything else, at most 1024 per type
    /// (a spread of states and encodings, not hundreds of similar ones).
    fn keep(&mut self, t: &Ty, j: &J) {
        fn fine(j: &J) -> String {
            match j {
                J::Num(_) => match num(j) {
                    Some(n) if n <= 64 => n.to_string(),
                    Some(n) => format!("b{}", 128 - n.leading_zeros()),
                    None => "?".into(),
                },
                J::Arr(xs) => format!("[{}]", xs.iter().map(fine).collect::<Vec<_>>().join(",")),
                J::Obj(kv) => format!("{{{}}}", kv.iter().map(|(k, v)| format!("{k}:{}", fine(v))).collect::<Vec<_>>().join(",")),
                other => other.render(),
            }
        }
        let k = tkey(t.peel_refs());
        let (shape, per) = match t.peel_refs() {
            Ty::Seq(_) => (self.shape(t, j), 4),
            _ => (fine(j), 1),
        };
        if self.harvest.get(&k).is_some_and(|h| h.len() >= 1024) {
            return;
        }
        let n = self.harvest_shapes.entry((k.clone(), shape)).or_default();
        if *n >= per {
            return;
        }
        let h = self.harvest.entry(k).or_default();
        if !h.contains(j) {
            *n += 1;
            h.push(j.clone());
        }
    }

    // -- outcome classes and mutation ----------------------------------------

    fn shape(&self, t: &Ty, j: &J) -> String {
        if let Some(a) = lanes_ty(t) {
            return self.shape(&a, j);
        }
        match (t.peel_refs(), j) {
            (Ty::Uint(_), J::Num(_)) => format!("b{}", num(j).map(|n| 128 - n.leading_zeros()).unwrap_or(0)),
            (Ty::Seq(_) | Ty::Array(..), J::Arr(xs)) => format!("L{}", xs.len()),
            (Ty::Option(_), J::Null) => "None".into(),
            (Ty::Option(e), J::Obj(kv)) => format!("Some({})", kv.first().map(|(_, x)| self.shape(e, x)).unwrap_or_default()),
            (Ty::Tuple(ts), J::Arr(xs)) => format!("({})", ts.iter().zip(xs).map(|(t, x)| self.shape(t, x)).collect::<Vec<_>>().join(",")),
            (Ty::Adt(id, args), _) => match (&self.krate.item(*id).kind, j) {
                (ItemKind::Struct(s), J::Obj(kv)) => format!("{{{}}}", s.fields.iter().zip(kv).map(|(f, (_, x))| self.shape(&f.ty.subst(args), x)).collect::<Vec<_>>().join(",")),
                (ItemKind::Struct(s), J::Arr(xs)) => format!("[{}]", s.fields.iter().zip(xs).map(|(f, x)| self.shape(&f.ty.subst(args), x)).collect::<Vec<_>>().join(",")),
                (ItemKind::Enum(_), J::Str(v)) => v.clone(),
                (ItemKind::Enum(en), J::Obj(kv)) => match kv.first() {
                    Some((vn, J::Arr(xs))) => {
                        let fs: Vec<Ty> = en.variants.iter().find(|v| &v.name == vn).map(|v| v.fields.iter().map(|f| f.ty.subst(args)).collect()).unwrap_or_default();
                        format!("{vn}({})", fs.iter().zip(xs).map(|(t, x)| self.shape(t, x)).collect::<Vec<_>>().join(","))
                    }
                    Some((vn, _)) => vn.clone(),
                    None => "?".into(),
                },
                _ => "?".into(),
            },
            (_, j) => j.render(),
        }
    }

    /// The outcome class of one evaluation.
    fn class(&self, p: &Plan<'_>, args: &[J], comps: &[J]) -> String {
        let mut k = String::new();
        for (i, (t, a)) in p.params.iter().zip(args).enumerate() {
            if !p.state_of.contains(&i) && !matches!(t.peel_refs(), Ty::Seq(_)) {
                k.push_str(&self.shape(t, a));
                k.push(';');
            }
        }
        k.push('|');
        for (ci, (t, j)) in p.comps.iter().zip(comps).enumerate() {
            match (ci < p.state_of.len(), t, j, &args.get(p.state_of.get(ci).copied().unwrap_or(usize::MAX))) {
                (true, Ty::Seq(_), J::Arr(after), Some(J::Arr(before))) => k.push_str(&format!("d{}", after.len() as i64 - before.len() as i64)),
                _ => k.push_str(&self.shape(t, j)),
            }
            k.push(';');
        }
        k
    }

    fn mutate(&mut self, t: &Ty, j: &J, depth: u32) -> J {
        if let Some(a) = lanes_ty(t) {
            return self.mutate(&a, j, depth);
        }
        let t = t.peel_refs().clone();
        match (&t, j) {
            (Ty::Bool, J::Bool(b)) => J::Bool(!b),
            (Ty::Uint(u), _) => {
                let max = u.max_value();
                let n = num(j).unwrap_or(0);
                let r = match self.rng.below(5) {
                    0 => n.wrapping_add(1) & max,
                    1 => n.wrapping_sub(1) & max,
                    2 => n ^ (1u128 << self.rng.below(u.bits() as u64)),
                    3 => (n << 7) & max,
                    _ => {
                        let p = self.pool(&t, 0);
                        p.get(self.rng.below(p.len() as u64) as usize).and_then(num).unwrap_or(0)
                    }
                };
                J::Num(r.to_string())
            }
            (Ty::Seq(e), J::Arr(xs)) => {
                let mut xs = xs.clone();
                let ep = self.pool(e, depth + 1);
                let pick = |g: &mut Gen<'_>| ep.get(g.rng.below(ep.len().max(1) as u64) as usize).cloned().unwrap_or(J::Num("0".into()));
                match self.rng.below(6) {
                    0 | 1 => {
                        let v = pick(self);
                        xs.push(v);
                    }
                    2 if !xs.is_empty() => {
                        xs.pop();
                    }
                    3 => {
                        let v = pick(self);
                        xs.insert(0, v);
                    }
                    _ if !xs.is_empty() => {
                        let i = self.rng.below(xs.len() as u64) as usize;
                        let v = self.mutate(e, &xs[i], depth + 1);
                        xs[i] = v;
                    }
                    _ => {
                        let v = pick(self);
                        xs.push(v);
                    }
                }
                J::Arr(xs)
            }
            (Ty::Array(e, _), J::Arr(xs)) if !xs.is_empty() => {
                let mut xs = xs.clone();
                let i = self.rng.below(xs.len() as u64) as usize;
                xs[i] = self.mutate(e, &xs[i], depth + 1);
                J::Arr(xs)
            }
            (Ty::Tuple(ts), J::Arr(xs)) if !ts.is_empty() && ts.len() == xs.len() => {
                let mut xs = xs.clone();
                let i = self.rng.below(xs.len() as u64) as usize;
                xs[i] = self.mutate(&ts[i], &xs[i], depth + 1);
                J::Arr(xs)
            }
            (Ty::Option(e), J::Null) => {
                let p = self.pool(e, depth + 1);
                match p.get(self.rng.below(p.len().max(1) as u64) as usize) {
                    Some(v) => J::Obj(vec![("Some".into(), v.clone())]),
                    None => J::Null,
                }
            }
            (Ty::Option(e), J::Obj(kv)) if self.rng.below(3) > 0 && !kv.is_empty() => J::Obj(vec![("Some".into(), self.mutate(e, &kv[0].1, depth + 1))]),
            (Ty::Option(_), _) => J::Null,
            (Ty::Adt(id, args), _) if depth < 4 => {
                if let Some((_, fields)) = self.fields_of(*id, args) {
                    if fields.is_empty() {
                        return j.clone();
                    }
                    // a harvested state, sometimes
                    if let Some(h) = self.harvest.get(&tkey(&t))
                        && !h.is_empty()
                        && self.rng.below(2) == 0
                    {
                        return h[self.rng.below(h.len() as u64) as usize].clone();
                    }
                    let i = self.rng.below(fields.len() as u64) as usize;
                    match j {
                        J::Obj(kv) => {
                            let mut kv = kv.clone();
                            if let Some(slot) = kv.iter_mut().find(|(k, _)| *k == fields[i].0) {
                                slot.1 = self.mutate(&fields[i].1, &slot.1, depth + 1);
                            }
                            J::Obj(kv)
                        }
                        J::Arr(xs) if xs.len() == fields.len() => {
                            let mut xs = xs.clone();
                            xs[i] = self.mutate(&fields[i].1, &xs[i], depth + 1);
                            J::Arr(xs)
                        }
                        other => other.clone(),
                    }
                } else {
                    let p = self.pool(&t, depth + 1);
                    p.get(self.rng.below(p.len().max(1) as u64) as usize).cloned().unwrap_or_else(|| j.clone())
                }
            }
            _ => j.clone(),
        }
    }

    /// Generates, evaluates and keeps the inputs of every plan.
    fn run(&mut self, plans: &[Plan<'_>], rep: &mut Report) -> Vec<Case> {
        let mut cases: Vec<Case> = Vec::new();
        let mut seen: Vec<HashSet<String>> = plans.iter().map(|_| HashSet::new()).collect();
        let mut classes: Vec<HashSet<String>> = plans.iter().map(|_| HashSet::new()).collect();
        let mut evals: Vec<usize> = vec![0; plans.len()];
        // inputs that showed a new outcome class (mutation parents), kept
        // across rounds
        let mut corpora: Vec<Vec<Vec<J>>> = plans.iter().map(|_| Vec::new()).collect();
        for round in 0..ROUNDS {
            for (pi, p) in plans.iter().enumerate() {
                let budget = EVALS * (round + 1) / ROUNDS;
                if evals[pi] >= budget || p.panic_only {
                    continue;
                }
                self.rng = Rng(SEED ^ meval::hash_str(&p.e.lifted) ^ (round as u64).wrapping_mul(0x9E37_79B9));
                let pools: Vec<Vec<J>> = p.params.iter().map(|t| self.pool(t, 0)).collect();
                // half of this round's evaluations for candidates, the rest
                // for mutants of the inputs that showed a new outcome class
                let fresh = ((budget - evals[pi]) / 2).clamp(1, INITIAL);
                let mut queue: Vec<Vec<J>> = combine(&pools, fresh, &mut self.rng);
                let corpus = &mut corpora[pi];
                let mut qi = 0;
                let mut guard = 0;
                while evals[pi] < budget && guard < budget * 8 {
                    guard += 1;
                    let args = if qi < queue.len() {
                        qi += 1;
                        queue[qi - 1].clone()
                    } else if corpus.is_empty() {
                        break;
                    } else {
                        let parent = corpus[self.rng.below(corpus.len() as u64) as usize].clone();
                        let i = self.rng.below(parent.len().max(1) as u64) as usize;
                        let mut child = parent.clone();
                        if let (Some(t), Some(a)) = (p.params.get(i), parent.get(i)) {
                            child[i] = self.mutate(t, a, 0);
                        }
                        child
                    };
                    if !seen[pi].insert(args.iter().map(J::render).collect::<Vec<_>>().join("\u{1}")) {
                        continue;
                    }
                    let mut reference = 0;
                    let r = self.eval(p, &args, &mut reference);
                    rep.entries[p.index].reference += reference;
                    match r {
                        Err(None) => {
                            rep.entries[p.index].rejected += 1;
                            continue;
                        }
                        Err(Some(e)) => {
                            evals[pi] += 1;
                            cases.push(Case { plan: pi, args, model: Err(e) });
                        }
                        Ok(comps) => {
                            evals[pi] += 1;
                            let cl = self.class(p, &args, &comps);
                            if classes[pi].insert(cl) {
                                corpus.push(args.clone());
                            }
                            for (t, j) in p.comps.iter().zip(&comps) {
                                self.harvest_value(t, j);
                            }
                            // the bytes a `BufMut` holds after a call are
                            // inputs for the functions that read buffers
                            for (ci, &i) in p.state_of.iter().enumerate() {
                                if p.e.params[i] == ParamPass::BufMut
                                    && let (J::Arr(before), J::Arr(after)) = (&args[i], &comps[ci])
                                    && after.starts_with(before)
                                {
                                    // the bytes this call wrote
                                    let t = p.comps[ci].clone();
                                    self.keep(&t, &J::Arr(after[before.len()..].to_vec()));
                                }
                            }
                            cases.push(Case { plan: pi, args, model: Ok(comps) });
                        }
                    }
                }
                queue.clear();
            }
        }
        // inputs inside each panic contract's panic region, on purpose
        for (pi, p) in plans.iter().enumerate() {
            if p.pre_dom.is_some() {
                evals[pi] += self.panic_region(pi, p, &mut seen[pi], &mut cases);
            }
        }
        for (pi, p) in plans.iter().enumerate() {
            rep.entries[p.index].cases = evals[pi];
            rep.entries[p.index].classes = classes[pi].len();
        }
        cases
    }

    /// Seeks inputs inside the panic region of `p`'s panic contract (its
    /// domain holds, its no-panic clause does not), on purpose: the
    /// coverage-driven inputs land there rarely (one or two of a function's
    /// first inputs, none for a function compared only there). Candidates
    /// are drawn from the parameters' pools (every small value, the powers
    /// of two ±1, the maximum, the states reached), then mutants of the
    /// inputs found, and only the domain and precondition checkers are
    /// evaluated on them; up to [`PANIC_INPUTS`] in all (counting those
    /// the coverage-driven search found) become cases (rustc must panic,
    /// L must give `Panic`). Returns the number added. Finding none is not
    /// an error here: the comparison's tally fails a panic contract
    /// compared on no input ([`panic_coverage`]).
    fn panic_region(&mut self, pi: usize, p: &Plan<'_>, seen: &mut HashSet<String>, cases: &mut Vec<Case>) -> usize {
        let (Some(chk), Some(dom)) = (p.pre, p.pre_dom) else { return 0 };
        let mut have = cases.iter().filter(|c| c.plan == pi && c.model.as_ref().err().is_some_and(|e| e == PANIC_CASE)).count();
        let mut found: Vec<Vec<J>> = Vec::new();
        let mut added = 0;
        self.rng = Rng(SEED ^ meval::hash_str(&p.e.lifted) ^ 0x7061_6e69_635f_7265);
        let pools: Vec<Vec<J>> = p.params.iter().map(|t| self.pool(t, 0)).collect();
        let mut queue = combine(&pools, PANIC_TRIES, &mut self.rng);
        let mut tries = 0;
        let mut qi = 0;
        while have < PANIC_INPUTS && tries < PANIC_TRIES {
            tries += 1;
            let args = if qi < queue.len() {
                qi += 1;
                queue[qi - 1].clone()
            } else if !found.is_empty() {
                let parent = found[self.rng.below(found.len() as u64) as usize].clone();
                let i = self.rng.below(parent.len().max(1) as u64) as usize;
                let mut child = parent.clone();
                if let (Some(t), Some(a)) = (p.params.get(i), parent.get(i)) {
                    child[i] = self.mutate(t, a, 0);
                }
                child
            } else if pools.iter().all(|x| !x.is_empty()) {
                pools.iter().map(|x| x[self.rng.below(x.len() as u64) as usize].clone()).collect()
            } else {
                break;
            };
            if !seen.insert(args.iter().map(J::render).collect::<Vec<_>>().join("\u{1}")) {
                continue;
            }
            let inside = match self.meets_pre(chk, p, &args) {
                Ok(false) => dom.is_none_or(|d| self.meets_pre(d, p, &args).unwrap_or(false)),
                _ => false,
            };
            if inside {
                found.push(args.clone());
                cases.push(Case { plan: pi, args, model: Err(PANIC_CASE.into()) });
                have += 1;
                added += 1;
            }
        }
        queue.clear();
        added
    }
}

/// Fails each panic contract of the checked functions that was compared on
/// no input: a contract is compared only on inputs of its panic region
/// where rustc panicked and the literal reading gave `Panic`
/// (`panics_seen`, by lifted function). A contract the check could not
/// compare (no checker of its precondition or domain, a skipped function,
/// no input found inside its condition) fails too, and so does a condition
/// that never holds on the function's domain, whose panic theorem would be
/// vacuous.
fn panic_coverage(krate: &Crate, entries: &[&ConformEntry], panics_seen: &std::collections::BTreeMap<String, usize>, rep: &mut Report) {
    for e in entries {
        let Some(f) = krate.find(&e.lifted).and_then(|id| krate.fn_def(id)) else { continue };
        if f.nopanic_clause().is_none() {
            continue;
        }
        if panics_seen.get(&e.lifted).copied().unwrap_or(0) == 0 {
            rep.errors.push(format!("`{}`: its panic contract was compared with rustc on no input (no generated input meets its condition on its domain, or the function could not be compared): a condition that never holds there would prove vacuously", e.lifted));
        }
    }
}

/// `0, 1, 2`, the maximum and every `2^k − 1, 2^k, 2^k + 1` below it.
fn boundary(bits: u32) -> Vec<u128> {
    let max = if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
    let mut v = vec![0, 1, 2, max, max - 1];
    for k in 1..bits {
        let p = 1u128 << k;
        v.extend([p - 1, p, p + 1]);
    }
    v.retain(|x| *x <= max);
    v
}

fn dedup(v: Vec<J>) -> Vec<J> {
    let mut out: Vec<J> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for x in v {
        if seen.insert(x.render()) {
            out.push(x);
        }
    }
    out
}

/// Argument tuples from per-parameter pools (at most `n`): the diagonal,
/// one parameter varied at a time, pairs of the first two, then
/// pseudo-random picks (as [`crate::mutate::eval::inputs`]).
fn combine(pools: &[Vec<J>], n: usize, rng: &mut Rng) -> Vec<Vec<J>> {
    let mut out: Vec<Vec<J>> = Vec::new();
    if pools.is_empty() {
        return vec![vec![]];
    }
    if pools.iter().any(|p| p.is_empty()) {
        return out;
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut push = |t: Vec<J>, out: &mut Vec<Vec<J>>| {
        let k = t.iter().map(J::render).collect::<Vec<_>>().join("\u{1}");
        if out.len() < n && seen.insert(k) {
            out.push(t);
        }
    };
    let longest = pools.iter().map(|p| p.len()).max().unwrap_or(0);
    for i in 0..longest {
        push(pools.iter().map(|p| p[i % p.len()].clone()).collect(), &mut out);
    }
    for j in 0..pools.len() {
        for v in &pools[j] {
            let mut t: Vec<J> = pools.iter().map(|p| p[0].clone()).collect();
            t[j] = v.clone();
            push(t, &mut out);
        }
    }
    if pools.len() >= 2 {
        for a in pools[0].iter().take(24) {
            for b in pools[1].iter().take(24) {
                let mut t: Vec<J> = pools.iter().map(|p| p[0].clone()).collect();
                t[0] = a.clone();
                t[1] = b.clone();
                push(t, &mut out);
            }
        }
    }
    let mut guard = 0;
    while out.len() < n && guard < n * 4 {
        guard += 1;
        let t: Vec<J> = pools.iter().map(|p| p[rng.below(p.len() as u64) as usize].clone()).collect();
        push(t, &mut out);
    }
    // a deterministic shuffle, so that a budget smaller than the list
    // still samples every strategy
    for i in (1..out.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        out.swap(i, j);
    }
    out
}

// ---------------------------------------------------------------------------
// the harness
// ---------------------------------------------------------------------------

/// The harness prelude (inside the harness module).
const PRELUDE: &str = r#"
    #![allow(warnings)]
    pub struct __T<'a>(pub ::core::str::SplitAsciiWhitespace<'a>);
    impl __T<'_> {
        pub fn n(&mut self) -> u128 {
            match self.0.next() {
                ::core::option::Option::Some(x) => match x.parse::<u128>() {
                    ::core::result::Result::Ok(v) => v,
                    ::core::result::Result::Err(_) => ::core::panic!("sandblaster harness: bad token"),
                },
                ::core::option::Option::None => ::core::panic!("sandblaster harness: missing token"),
            }
        }
    }
    pub trait __W {
        fn w(&self, o: &mut ::std::string::String);
    }
    // a result returned by reference (`Deref::deref`) is written as its value
    impl<A: __W + ?Sized> __W for &A {
        fn w(&self, o: &mut ::std::string::String) { __W::w(&**self, o); }
    }
    macro_rules! __w_num {
        ($($t:ty),*) => { $(impl __W for $t { fn w(&self, o: &mut ::std::string::String) { o.push_str(&::std::format!("{}", self)); } })* };
    }
    __w_num!(u8, u16, u32, u64, usize);
    // a `u128` as the lift reads it: its (low, high) 64-bit words
    impl __W for u128 {
        fn w(&self, o: &mut ::std::string::String) { o.push('['); __W::w(&(*self as u64), o); o.push(','); __W::w(&((*self >> 64) as u64), o); o.push(']'); }
    }
    impl __W for bool {
        fn w(&self, o: &mut ::std::string::String) { o.push_str(if *self { "true" } else { "false" }); }
    }
    impl __W for i16 {
        fn w(&self, o: &mut ::std::string::String) { o.push('['); __W::w(&(*self as u16), o); o.push(']'); }
    }
    impl __W for i32 {
        fn w(&self, o: &mut ::std::string::String) { o.push('['); __W::w(&(*self as u32), o); o.push(']'); }
    }
    impl __W for i64 {
        fn w(&self, o: &mut ::std::string::String) { o.push('['); __W::w(&(*self as u64), o); o.push(']'); }
    }
    impl __W for () {
        fn w(&self, o: &mut ::std::string::String) { o.push_str("null"); }
    }
    impl __W for ::bytes::TryGetError {
        fn w(&self, o: &mut ::std::string::String) { o.push_str("null"); }
    }
    impl<A: __W> __W for ::core::option::Option<A> {
        fn w(&self, o: &mut ::std::string::String) {
            match self {
                ::core::option::Option::None => o.push_str("null"),
                ::core::option::Option::Some(a) => { o.push_str("{\"Some\":"); __W::w(a, o); o.push('}'); }
            }
        }
    }
    impl<A: __W, B: __W> __W for ::core::result::Result<A, B> {
        fn w(&self, o: &mut ::std::string::String) {
            match self {
                ::core::result::Result::Ok(a) => { o.push_str("{\"Ok\":["); __W::w(a, o); o.push_str("]}"); }
                ::core::result::Result::Err(b) => { o.push_str("{\"Err\":["); __W::w(b, o); o.push_str("]}"); }
            }
        }
    }
    impl<A: __W> __W for ::std::vec::Vec<A> {
        fn w(&self, o: &mut ::std::string::String) {
            o.push('[');
            for (i, x) in self.iter().enumerate() { if i > 0 { o.push(','); } __W::w(x, o); }
            o.push(']');
        }
    }
    impl<A: __W, const N: usize> __W for [A; N] {
        fn w(&self, o: &mut ::std::string::String) {
            o.push('[');
            for (i, x) in self.iter().enumerate() { if i > 0 { o.push(','); } __W::w(x, o); }
            o.push(']');
        }
    }
    impl<A: __W> __W for (A,) {
        fn w(&self, o: &mut ::std::string::String) { o.push('['); __W::w(&self.0, o); o.push(']'); }
    }
    impl<A: __W, B: __W> __W for (A, B) {
        fn w(&self, o: &mut ::std::string::String) { o.push('['); __W::w(&self.0, o); o.push(','); __W::w(&self.1, o); o.push(']'); }
    }
    impl<A: __W, B: __W, C: __W> __W for (A, B, C) {
        fn w(&self, o: &mut ::std::string::String) { o.push('['); __W::w(&self.0, o); o.push(','); __W::w(&self.1, o); o.push(','); __W::w(&self.2, o); o.push(']'); }
    }
"#;

/// Generated readers and writers, by Rust type.
struct Emit<'g, 'a> {
    g: &'g Gen<'a>,
    /// By Rust type: the reader's name as its users call it, its code and
    /// the module that holds it (in-place harnesses; empty otherwise).
    readers: BTreeMap<String, (String, String, String)>,
    /// By Rust type: the writer's code and the module that holds it.
    writers: BTreeMap<String, (String, String)>,
}

impl Emit<'_, '_> {
    /// The reader function of a type (`__r3`), generated on first use.
    fn reader(&mut self, t: &Ty) -> Result<String, String> {
        let t = t.peel_refs();
        let rt = self.g.rust_ty(t)?;
        if let Some((name, _, _)) = self.readers.get(&rt) {
            return Ok(name.clone());
        }
        let local = format!("__r{}", self.readers.len());
        // (an in-place harness spreads its readers over the modules whose
        // private fields they build: every use names the reader's path)
        let home = self.g.ip_home(t);
        let name = if home.is_empty() { local.clone() } else { format!("{home}::{local}") };
        self.readers.insert(rt.clone(), (name.clone(), String::new(), home.clone()));
        let body = match t {
            // the lanes, then the vector of them (`transmute`: harness code,
            // never verified; lane 0 at the lowest address)
            Ty::Vector(_) => {
                let a = lanes_ty(t).ok_or("lanes")?;
                let (r, at) = (self.reader(&a)?, self.g.rust_ty(&a)?);
                format!("{{ let a: {at} = {r}(t); unsafe {{ ::core::mem::transmute::<{at}, {rt}>(a) }} }}")
            }
            Ty::Bool => "t.n() != 0".to_string(),
            Ty::Uint(u) => format!("t.n() as {}", u.name()),
            Ty::Tuple(ts) if ts.is_empty() => "()".into(),
            Ty::Tuple(ts) => {
                let rs = ts.iter().map(|x| self.reader(x).map(|r| format!("{r}(t)"))).collect::<Result<Vec<_>, _>>()?;
                format!("({},)", rs.join(", "))
            }
            Ty::Array(e, n) => {
                let r = self.reader(e)?;
                format!("{{ let mut v = ::std::vec::Vec::new(); for _ in 0..{n}usize {{ v.push({r}(t)); }} match <{rt}>::try_from(v) {{ ::core::result::Result::Ok(a) => a, ::core::result::Result::Err(_) => ::core::unreachable!() }} }}")
            }
            Ty::Seq(e) | Ty::Slice(e) => {
                let r = self.reader(e)?;
                format!("{{ let n = t.n() as usize; let mut v = ::std::vec::Vec::with_capacity(n); for _ in 0..n {{ v.push({r}(t)); }} v }}")
            }
            Ty::Option(e) => {
                let r = self.reader(e)?;
                format!("if t.n() == 0 {{ ::core::option::Option::None }} else {{ ::core::option::Option::Some({r}(t)) }}")
            }
            Ty::Adt(id, _) if self.g.signed_bits(*id).is_some() => {
                let b = self.g.signed_bits(*id).unwrap_or(0);
                format!("(t.n() as u{b}) as i{b}")
            }
            Ty::Adt(id, args) => {
                let (_, ep) = self.g.adt_paths(*id, args)?;
                match &self.g.krate.item(*id).kind {
                    ItemKind::Struct(s) => self.ctor(&ep, s.shape, &s.fields, args)?,
                    ItemKind::Enum(en) => {
                        let mut arms = Vec::new();
                        for (i, v) in en.variants.iter().enumerate() {
                            arms.push(format!("{i} => {}", self.ctor(&format!("{ep}::{}", v.name), v.shape, &v.fields, args)?));
                        }
                        format!("match t.n() {{ {}, _ => ::core::unreachable!() }}", arms.join(", "))
                    }
                    _ => return Err("not a data type".into()),
                }
            }
            other => return Err(format!("no reader for `{other:?}`")),
        };
        let vis = if home.is_empty() { "" } else { "pub " };
        let code = format!("    {vis}fn {local}(t: &mut __T<'_>) -> {rt} {{ {body} }}\n");
        self.readers.insert(rt, (name.clone(), code, home));
        Ok(name)
    }

    fn ctor(&mut self, path: &str, shape: Shape, fields: &[FieldDef], args: &[Ty]) -> Result<String, String> {
        let mut parts = Vec::new();
        // (an in-place struct's fields as the source writes them)
        let host: Option<Vec<(String, String)>> = self.g.ip.as_ref().and_then(|ip| ip.host_fields.get(path.rsplit("::").next().unwrap_or(path)).cloned());
        for f in fields {
            let ft = f.ty.subst(args);
            // a `PhantomData` field (its type arguments erased by the lift)
            let mut value = if self.g.ip.is_some() && self.g.is_phantom(&ft) { "::core::marker::PhantomData".to_string() } else { format!("{}(t)", self.reader(&ft)?) };
            if let Some(h) = host.as_ref().and_then(|h| h.iter().find(|(n, _)| Some(n) == f.name.as_ref()))
            {
                value = in_place::host_field_value(&h.1, value);
            }
            parts.push(match shape {
                Shape::Named => format!("{}: {value}", f.name.clone().unwrap_or_default()),
                _ => value,
            });
        }
        Ok(match shape {
            Shape::Named => format!("{path} {{ {} }}", parts.join(", ")),
            Shape::Tuple => format!("{path}({})", parts.join(", ")),
            Shape::Unit => path.to_string(),
        })
    }

    /// Makes sure the writer of a type exists (data types of the module
    /// and of the host models; the prelude has the others).
    fn writer(&mut self, t: &Ty) -> Result<(), String> {
        let t = t.peel_refs();
        match t {
            // a vector is written as the array of its lanes
            Ty::Vector(_) => {
                let rt = self.g.rust_ty(t)?;
                if self.writers.contains_key(&rt) {
                    return Ok(());
                }
                let at = self.g.rust_ty(&lanes_ty(t).ok_or("lanes")?)?;
                let code = format!("    impl __W for {rt} {{ fn w(&self, o: &mut ::std::string::String) {{ let a: {at} = unsafe {{ ::core::mem::transmute::<{rt}, {at}>(*self) }}; __W::w(&a, o); }} }}\n");
                self.writers.insert(rt, (code, self.g.ip_home(t)));
                Ok(())
            }
            Ty::Tuple(ts) => {
                if ts.len() > 3 {
                    return Err("tuples of more than 3 components have no writer".into());
                }
                ts.iter().try_for_each(|x| self.writer(x))
            }
            Ty::Array(e, _) | Ty::Seq(e) | Ty::Slice(e) | Ty::Option(e) => self.writer(e),
            Ty::Adt(id, _) if self.g.signed_bits(*id).is_some() => Ok(()),
            // (the in-place prelude writes every `PhantomData`)
            Ty::Adt(..) if self.g.ip.is_some() && self.g.is_phantom(t) => Ok(()),
            Ty::Adt(id, args) => {
                let path = self.g.krate.item(*id).path.to_string();
                if path == "crate::__lift::Result" {
                    return args.iter().try_for_each(|x| self.writer(x));
                }
                if path == "crate::__lift::TryGetError" {
                    return Ok(());
                }
                let (rt, ep) = self.g.adt_paths(*id, args)?;
                if self.writers.contains_key(&rt) {
                    return Ok(());
                }
                let home = self.g.ip_home(t);
                self.writers.insert(rt.clone(), (String::new(), home.clone()));
                let q = |s: &str| format!("{s:?}");
                let body = match &self.g.krate.item(*id).kind {
                    ItemKind::Struct(s) => {
                        for f in &s.fields {
                            self.writer(&f.ty.subst(args))?;
                        }
                        match s.shape {
                            Shape::Named => {
                                let parts: Vec<String> = s.fields.iter().map(|f| {
                                    let n = f.name.clone().unwrap_or_default();
                                    format!("o.push_str({}); __W::w(&self.{n}, o);", q(&format!("\"{n}\":")))
                                }).collect();
                                format!("o.push('{{'); {} o.push('}}');", parts.join(" o.push(','); "))
                            }
                            Shape::Tuple => {
                                let parts: Vec<String> = (0..s.fields.len()).map(|i| format!("__W::w(&self.{i}, o);")).collect();
                                format!("o.push('['); {} o.push(']');", parts.join(" o.push(','); "))
                            }
                            Shape::Unit => "o.push_str(\"null\");".into(),
                        }
                    }
                    ItemKind::Enum(en) => {
                        let mut arms = Vec::new();
                        for v in &en.variants {
                            for f in &v.fields {
                                self.writer(&f.ty.subst(args))?;
                            }
                            let vn = &v.name;
                            arms.push(match v.shape {
                                Shape::Unit => format!("{ep}::{vn} => o.push_str({}),", q(&format!("\"{vn}\""))),
                                Shape::Tuple => {
                                    let xs: Vec<String> = (0..v.fields.len()).map(|i| format!("x{i}")).collect();
                                    let ws: Vec<String> = xs.iter().map(|x| format!("__W::w({x}, o);")).collect();
                                    format!("{ep}::{vn}({}) => {{ o.push_str({}); {} o.push_str(\"]}}\"); }}", xs.join(", "), q(&format!("{{\"{vn}\":[")), ws.join(" o.push(','); "))
                                }
                                Shape::Named => {
                                    let ns: Vec<String> = v.fields.iter().map(|f| f.name.clone().unwrap_or_default()).collect();
                                    let ws: Vec<String> = ns.iter().map(|n| format!("o.push_str({}); __W::w({n}, o);", q(&format!("\"{n}\":")))).collect();
                                    format!("{ep}::{vn} {{ {} }} => {{ o.push_str({}); {} o.push_str(\"}}}}\"); }}", ns.join(", "), q(&format!("{{\"{vn}\":{{")), ws.join(" o.push(','); "))
                                }
                            });
                        }
                        // a host model has the variants the lifted code
                        // builds; the host's enum may have more (written as
                        // a value no model output has: a mismatch if met)
                        if self.g.ip_host_model(*id) {
                            arms.push("#[allow(unreachable_patterns)] _ => o.push_str(\"\\\"(a variant the host model does not have)\\\"\"),".into());
                        }
                        format!("match self {{ {} }}", arms.join(" "))
                    }
                    _ => return Err("not a data type".into()),
                };
                let code = format!("    impl __W for {rt} {{ fn w(&self, o: &mut ::std::string::String) {{ {body} }} }}\n");
                self.writers.insert(rt, (code, home));
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// The input tokens of a value (the order the readers read them).
fn tokens(g: &Gen<'_>, t: &Ty, j: &J, out: &mut Vec<String>) -> Result<(), String> {
    if let Some(a) = lanes_ty(t) {
        return tokens(g, &a, j, out);
    }
    let bad = || format!("the value {} does not fit {t:?}", j.render());
    match (t.peel_refs(), j) {
        (Ty::Bool, J::Bool(b)) => out.push(if *b { "1" } else { "0" }.into()),
        (Ty::Uint(_), J::Num(n)) => out.push(n.clone()),
        (Ty::Tuple(ts), J::Null) if ts.is_empty() => {}
        (Ty::Tuple(ts), J::Arr(xs)) if ts.len() == xs.len() => {
            for (t, x) in ts.iter().zip(xs) {
                tokens(g, t, x, out)?;
            }
        }
        (Ty::Array(e, _), J::Arr(xs)) => {
            for x in xs {
                tokens(g, e, x, out)?;
            }
        }
        (Ty::Seq(e) | Ty::Slice(e), J::Arr(xs)) => {
            out.push(xs.len().to_string());
            for x in xs {
                tokens(g, e, x, out)?;
            }
        }
        (Ty::Option(_), J::Null) => out.push("0".into()),
        (Ty::Option(e), J::Obj(kv)) if kv.len() == 1 => {
            out.push("1".into());
            tokens(g, e, &kv[0].1, out)?;
        }
        (Ty::Adt(id, args), _) => match &g.krate.item(*id).kind {
            ItemKind::Struct(s) => field_tokens(g, &s.fields, s.shape, args, j, out)?,
            ItemKind::Enum(en) => {
                let (vn, payload) = match j {
                    J::Str(n) => (n.clone(), J::Null),
                    J::Obj(kv) if kv.len() == 1 => (kv[0].0.clone(), kv[0].1.clone()),
                    _ => return Err(bad()),
                };
                let (i, v) = en.variants.iter().enumerate().find(|(_, v)| v.name == vn).ok_or_else(bad)?;
                out.push(i.to_string());
                field_tokens(g, &v.fields, v.shape, args, &payload, out)?;
            }
            _ => return Err(bad()),
        },
        _ => return Err(bad()),
    }
    Ok(())
}

fn field_tokens(g: &Gen<'_>, fields: &[FieldDef], shape: Shape, args: &[Ty], j: &J, out: &mut Vec<String>) -> Result<(), String> {
    for (i, f) in fields.iter().enumerate() {
        let x = match (shape, j) {
            (Shape::Named, J::Obj(kv)) => kv.iter().find(|(k, _)| Some(k) == f.name.as_ref()).map(|(_, v)| v.clone()),
            (_, J::Arr(xs)) => xs.get(i).cloned(),
            _ => None,
        }
        .ok_or_else(|| format!("field {i} missing in {}", j.render()))?;
        tokens(g, &f.ty.subst(args), &x, out)?;
    }
    Ok(())
}

/// The harness function of one plan (`__e{pi}`): reads the inputs, calls
/// the original and writes the states and the result.
fn entry_fn(em: &mut Emit<'_, '_>, g: &Gen<'_>, pi: usize, p: &Plan<'_>, vis: &str) -> Result<String, String> {
    let mut s = format!("    {vis}fn __e{pi}(t: &mut __T<'_>) -> ::std::string::String {{\n");
    let mut call_args = Vec::new();
    for (i, (pass, t)) in p.e.params.iter().zip(&p.params).enumerate() {
        let r = em.reader(t)?;
        let rt = g.rust_ty(t)?;
        // (a library newtype the lift reads as its field: converted)
        let cv = |a: String| match g.ip_cv(t) {
            Some(f) => cv_expr(&f, t, &a),
            None => a,
        };
        match pass {
            ParamPass::Value => {
                s.push_str(&format!("        let a{i}: {rt} = {r}(t);\n"));
                call_args.push(cv(format!("a{i}")));
            }
            // (a slice is passed as the whole of the vector read; a slice of
            // slices as the slices of its vectors)
            ParamPass::Ref if matches!(t, Ty::Ref(x) if matches!(**x, Ty::Slice(_))) => {
                let of_slices = matches!(t, Ty::Ref(x) if matches!(&**x, Ty::Slice(e) if matches!(&**e, Ty::Ref(y) if matches!(**y, Ty::Slice(_)))));
                let b = if of_slices { format!("a{i}.iter().map(|x| &x[..]).collect()") } else { cv(format!("a{i}")) };
                s.push_str(&format!("        let a{i}: {rt} = {r}(t);\n        let b{i}: ::std::vec::Vec<_> = {b};\n"));
                call_args.push(format!("&b{i}[..]"));
            }
            ParamPass::Ref => {
                s.push_str(&format!("        let a{i}: {rt} = {r}(t);\n"));
                call_args.push(format!("&{}", cv(format!("a{i}"))));
            }
            ParamPass::StateMut | ParamPass::VecMut => {
                s.push_str(&format!("        let mut a{i} = {};\n", cv(format!("{r}(t)"))));
                call_args.push(format!("&mut a{i}"));
            }
            ParamPass::OptVec => {
                s.push_str(&format!("        let mut a{i}: ::core::option::Option<::std::vec::Vec<_>> = {};\n", cv(format!("{r}(t)"))));
                call_args.push(format!("a{i}.as_mut()"));
            }
            // the byte strings, iterated by a slice iterator (its `as_slice`
            // is what it has not yielded)
            ParamPass::BytesIter => {
                s.push_str(&format!("        let v{i}: {rt} = {r}(t);\n        let s{i}: ::std::vec::Vec<&[u8]> = v{i}.iter().map(|x| &x[..]).collect();\n        let mut a{i} = s{i}.iter();\n"));
                call_args.push(format!("&mut a{i}"));
            }
            ParamPass::MutRef | ParamPass::BufMut => {
                s.push_str(&format!("        let mut a{i}: {rt} = {r}(t);\n"));
                call_args.push(format!("&mut a{i}"));
            }
            ParamPass::Buf => {
                s.push_str(&format!("        let v{i}: {rt} = {r}(t);\n        let mut a{i}: &[u8] = &v{i}[..];\n"));
                call_args.push(format!("&mut a{i}"));
            }
        }
    }
    for t in &p.comps {
        em.writer(t)?;
    }
    // (`unsafe`: a `#[target_feature]` original is called from the
    // harness, which is not compiled with its features; the CPU running the
    // check has them, or the call is not made: docs/mir-lift.md §20.9)
    s.push_str(&format!("        let ret = unsafe {{ {}({}) }};\n        let mut o = ::std::string::String::new();\n        o.push('[');\n", p.callee, call_args.join(", ")));
    let mut first = true;
    for &i in &p.state_of {
        if !first {
            s.push_str("        o.push(',');\n");
        }
        first = false;
        match p.e.params[i] {
            ParamPass::Buf => s.push_str(&format!("        __W::w(&a{i}.to_vec(), &mut o);\n")),
            ParamPass::BytesIter => s.push_str(&format!("        __W::w(&a{i}.as_slice().iter().map(|x| x.to_vec()).collect::<::std::vec::Vec<::std::vec::Vec<u8>>>(), &mut o);\n")),
            _ => s.push_str(&format!("        __W::w(&a{i}, &mut o);\n")),
        }
    }
    if p.e.opaque_ret {
        // (an opaque result is not read back: on a panic input rustc must
        // panic before returning it)
        s.push_str("        let _ = ret;\n");
    } else if p.e.has_ret {
        if !first {
            s.push_str("        o.push(',');\n");
        }
        s.push_str("        __W::w(&ret, &mut o);\n");
    } else {
        s.push_str("        let () = ret;\n");
    }
    s.push_str("        o.push(']');\n        o\n    }\n");
    Ok(s)
}

/// `a` (a value of the lifted type `t`) converted by the harness's `__cv`
/// (`cv`, its path) wherever `t` holds an array: the identity, or the
/// library newtype the original takes there (inferred from the call).
fn cv_expr(cv: &str, t: &Ty, a: &str) -> String {
    fn holds_array(t: &Ty) -> bool {
        match t {
            Ty::Array(..) => true,
            Ty::Ref(x) | Ty::Option(x) | Ty::Seq(x) | Ty::Slice(x) => holds_array(x),
            Ty::Tuple(ts) => ts.iter().any(holds_array),
            _ => false,
        }
    }
    if !holds_array(t) {
        return a.to_string();
    }
    match t {
        Ty::Array(..) => format!("{cv}({a})"),
        Ty::Ref(x) => cv_expr(cv, x, a),
        Ty::Option(x) => format!("{a}.map(|x| {})", cv_expr(cv, x, "x")),
        Ty::Seq(x) | Ty::Slice(x) => format!("{a}.into_iter().map(|x| {}).collect::<::std::vec::Vec<_>>()", cv_expr(cv, x, "x")),
        Ty::Tuple(ts) => {
            let xs: Vec<String> = (0..ts.len()).map(|i| format!("x{i}")).collect();
            let cs: Vec<String> = ts.iter().zip(&xs).map(|(t, x)| cv_expr(cv, t, x)).collect();
            format!("{{ let ({},) = {a}; ({},) }}", xs.join(", "), cs.join(", "))
        }
        _ => a.to_string(),
    }
}

/// Writes, compiles and runs the harness; returns its output line by case.
fn harness(g: &Gen<'_>, plans: &[Plan<'_>], cases: &[Case], src: &str, hosts: &[(String, String)], cfg: &Config) -> Result<Vec<String>, String> {
    let mut em = Emit { g, readers: BTreeMap::new(), writers: BTreeMap::new() };
    let mut fns = String::new();
    let mut arms = Vec::new();
    for (pi, p) in plans.iter().enumerate() {
        fns.push_str(&entry_fn(&mut em, g, pi, p, "")?);
        arms.push(format!("{pi} => __e{pi}(&mut t)"));
    }
    let mut module = format!("\n#[doc(hidden)]\npub mod {HARNESS_MOD} {{{PRELUDE}");
    for (_, code, _) in em.readers.values() {
        module.push_str(code);
    }
    for (code, _) in em.writers.values() {
        module.push_str(code);
    }
    module.push_str(&fns);
    module.push_str(&format!(
        r#"    pub fn main() {{
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
"#,
        arms.join(", ")
    ));
    let dir = &cfg.work_dir;
    let w = |name: &str, text: &str| std::fs::write(dir.join(name), text).map_err(|e| format!("cannot write `{}`: {e}", dir.join(name).display()));
    w("bytes.rs", BYTES_SHIM)?;
    let module_name = &g.module;
    w(&format!("lifted_{module_name}.rs"), &format!("{src}{module}"))?;
    let mut root = String::from("#![allow(warnings)]\n");
    root.push_str(HOST_SHIM);
    let has_error = hosts.iter().any(|(_, t)| t.contains("enum Error"));
    if has_error {
        root.push_str("\npub trait Read: Sized {\n    type Cfg: Clone + Send + Sync + 'static;\n    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> ::core::result::Result<Self, Error>;\n}\n");
    }
    for (name, text) in hosts {
        w(&format!("host_{name}.rs"), text)?;
        root.push_str(&format!("\n#[path = \"host_{name}.rs\"]\npub mod {name};\npub use self::{name}::*;\n"));
    }
    root.push_str(&format!("\n#[path = \"lifted_{module_name}.rs\"]\npub mod {module_name};\n\nfn main() {{\n    {module_name}::{HARNESS_MOD}::main();\n}}\n"));
    w("main.rs", &root)?;
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
    w("cases.txt", &text)?;
    // compile: the buffer model crate, then the harness
    let rustc = |args: &[&str]| -> Result<(), String> {
        let o = Command::new(&cfg.rustc).current_dir(dir).args(args).env_remove("RUSTC_WRAPPER").output().map_err(|e| format!("cannot run `{}`: {e}", cfg.rustc.display()))?;
        if !o.status.success() {
            return Err(format!("rustc failed on the harness (`{}`): {}", dir.display(), String::from_utf8_lossy(&o.stderr).lines().take(40).collect::<Vec<_>>().join("\n")));
        }
        Ok(())
    };
    let ed = format!("--edition={}", cfg.edition);
    rustc(&["--crate-type=rlib", "--crate-name=bytes", &ed, "-Coverflow-checks=on", "-Cdebug-assertions=on", "-o", "libbytes.rlib", "bytes.rs"])?;
    let exe = if cfg!(windows) { "harness.exe" } else { "harness" };
    rustc(&["--crate-type=bin", "--crate-name=sandblaster_conformance", &ed, "-Coverflow-checks=on", "-Cdebug-assertions=on", "-Copt-level=1", "--extern", "bytes=libbytes.rlib", "-o", exe, "main.rs"])?;
    run_harness(&dir.join(exe), dir, cases.len())
}

/// Runs a built harness on `dir/cases.txt`; returns its output line by case.
fn run_harness(exe: &Path, dir: &Path, n: usize) -> Result<Vec<String>, String> {
    // run
    let out_path = dir.join("outputs.txt");
    let out_file = std::fs::File::create(&out_path).map_err(|e| format!("cannot create `{}`: {e}", out_path.display()))?;
    let mut child = Command::new(exe).arg(dir.join("cases.txt")).stdout(Stdio::from(out_file)).stderr(Stdio::null()).spawn().map_err(|e| format!("cannot run the harness: {e}"))?;
    let t = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => break,
            Ok(Some(st)) => return Err(format!("the harness exited with {st}")),
            Ok(None) if t.elapsed() > RUN_TIMEOUT => {
                let _ = child.kill();
                return Err(format!("the harness did not finish within {}s", RUN_TIMEOUT.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(format!("waiting for the harness: {e}")),
        }
    }
    let text = std::fs::read_to_string(&out_path).map_err(|e| format!("cannot read `{}`: {e}", out_path.display()))?;
    let mut outs = vec![String::new(); n];
    for line in text.lines() {
        let (i, rest) = line.split_once('\t').ok_or_else(|| format!("bad harness line `{line}`"))?;
        let i: usize = i.parse().map_err(|_| format!("bad harness line `{line}`"))?;
        if i < outs.len() {
            outs[i] = rest.to_string();
        }
    }
    Ok(outs)
}

/// Compares the lifted model with rustc's outputs; returns rustc's outputs
/// read (by case) for the comparison of the literal reading.
fn compare(g: &Gen<'_>, plans: &[Plan<'_>], cases: &[Case], outputs: &[String], rep: &mut Report) -> Vec<Result<Vec<J>, String>> {
    let _ = g;
    let mut read = Vec::new();
    for (c, o) in cases.iter().zip(outputs) {
        let p = &plans[c.plan];
        let input = format!("({})", c.args.iter().map(J::render).collect::<Vec<_>>().join(", "));
        let rustc: Result<Vec<J>, String> = if let Some(msg) = o.strip_prefix("PANIC\t") {
            Err(format!("a panic ({msg})"))
        } else if o.is_empty() {
            Err("no output".into())
        } else {
            match J::parse(o) {
                Ok(J::Arr(xs)) if xs.len() == p.comps.len() => Ok(xs),
                Ok(other) => Err(format!("an unexpected output {}", other.render())),
                Err(e) => Err(format!("unreadable output ({e})")),
            }
        };
        let show = |r: &Result<Vec<J>, String>| match r {
            Ok(xs) if xs.len() == 1 => xs[0].render(),
            Ok(xs) => format!("[{}]", xs.iter().map(J::render).collect::<Vec<_>>().join(", ")),
            Err(e) => e.clone(),
        };
        // (an input where the panic contract says the function panics: rustc must panic)
        let panic_case = c.model.as_ref().err().is_some_and(|e| e == PANIC_CASE);
        let model: Result<Vec<J>, String> = c.model.clone().map_err(|e| if panic_case { e } else { format!("no value (kernel evaluation failed: {e})") });
        let same = matches!((&model, &rustc), (Ok(a), Ok(b)) if a == b) || (panic_case && rustc.as_ref().is_err_and(|e| e.starts_with("a panic (")));
        if !same {
            rep.mismatches.push(Mismatch { lifted: p.e.lifted.clone(), callee: p.callee.clone(), input, model: show(&model), rustc: show(&rustc) });
        }
        read.push(rustc);
    }
    read
}

/// The part of the cache key the literal reading's comparison adds: the
/// generator of L and its library (`mir::checked::generator_hash`) and the
/// MIR it reads.
fn literal_key(c: &Checked) -> String {
    let mut k = format!("literal-generator {}\n", crate::mir::checked::generator_hash());
    for mm in &c.lift_facts.mir_loaded {
        k.push_str(&format!("mir {} {}\n", mm.loaded.m.module, hex(&sha256(format!("{:?}{:?}", mm.loaded.m.fns, mm.loaded.m.adts).as_bytes()))));
    }
    k.push_str(&format!("contracts {}\n", hex(&sha256(format!("{:?}", c.lift_facts.mir_contracts).as_bytes()))));
    k
}
