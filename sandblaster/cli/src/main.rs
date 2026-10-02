//! `sandblaster` command line (DESIGN.md §10.2).
//!
//! Every command that states a crate verdict runs the **crate path**
//! (`driver::build_crate`, the same pipeline as `sandblaster::build::compile`):
//! the proofs, every §15 gate (boundary, examples and coverage, sections,
//! law rules, `SPEC.lock`, spec mutation), the optimizer, the printer, the
//! round trip and the emission-chain check. Only a crate verdict prints
//! `VERIFIED` or exits 0; there is no option that skips or weakens a proof
//! or a gate.
//!
//! * `sandblaster check <crate-dir|root.rs> [--target <arch>]` — the crate
//!   path; writes nothing. Prints diagnostics and a summary (proof counts,
//!   each gate's outcome, the hash of the file the build would emit); exit
//!   0 only with a verdict.
//! * `sandblaster emit <crate-dir|root.rs> [--target <arch>]` — the crate
//!   path; prints the generated Rust code (exactly what the build writes to
//!   `OUT_DIR/sandblaster.rs`, `STATUS: VERIFIED + OPTIMIZED`) to stdout, and
//!   nothing without a verdict.
//! * `sandblaster report <crate-dir|root.rs> [--target <arch>]` — the crate
//!   path; prints the JSON report the build writes (also without a verdict:
//!   it explains the failure); exit 0 only with a verdict.
//! * `sandblaster spec <crate-dir|root.rs> [--target <arch>]` — the crate
//!   path, then the spec sheet (DESIGN.md §15.6): per item the source text,
//!   the de-elaborated fully parenthesized statement and the kernel
//!   statement, and how the lock differs (each change classified in the
//!   kernel). Exit 0 only with a verdict. Writes nothing.
//!   * `--accept [ITEM…]` — runs every gate except the lock match
//!     (`LockUse::Accepting`) and, only if they pass, writes the root's
//!     lock (`SPEC.lock`, or `SPEC.<stem>.lock` for a root not named
//!     `mod.rs`/`lib.rs`) with every item and the toolchain header, or only
//!     the named items (keys as the sheet prints them; `toolchain` names
//!     the header). This is the only way a lock is written (never the
//!     build, never an environment variable).
//!   * `--accept --equivalent-only` — after a toolchain upgrade: re-accepts
//!     the toolchain header and only the items whose new statement is
//!     kernel-proven equivalent to the locked one.
//!   * `--preview <file>` — a review tool (no verdict): the crate path,
//!     then writes the lock `--accept` would write (every item of the
//!     computed review surface and the toolchain header) to `<file>`, never
//!     to a `SPEC*.lock`, and prints the item counts (locked now, previewed,
//!     proof internals left out). Needs the proofs to go through, not the
//!     gates: a preview of a lock that no longer matches is its purpose.
//!   * `--diff <rev-or-path>` — a stage tool (no verdict): elaborates the
//!     old revision (a git revision of the repository — every file the old
//!     revision reads comes from that revision — or another crate
//!     directory) and the current one in separate kernel environments and
//!     classifies each changed item: strengthened, weakened, equivalent or
//!     unrelated.
//! * `sandblaster coverage <crate-dir|root.rs> [--json] [--no-sheet]
//!   [--mutants-max N] [--time-budget SECS] [--only ITEM…] [--target <arch>]`
//!   — DESIGN.md §15.10: the crate path (its gate diagnostics on stderr),
//!   then an **exploration run** of the counterexample engine (§15.9: spec
//!   and implementation mutants, bounded by `--mutants-max` or
//!   `SANDBLASTER_MUTANTS_MAX`, `--time-budget`, `--only`; a progress line
//!   per batch on stderr) and its report: per function its safety
//!   obligations, refinement, laws, section, kill rates, examples and
//!   outcome coverage, the law sensitivity table (LR8) and the spec sheet;
//!   `--json` prints the same as JSON. The exploration options shape the
//!   report only, never the gate. Exit 0 only with a verdict.
//! * `sandblaster eval <crate-dir|root.rs> <fn> <args-json> [--target <arch>]`
//!   — a stage tool: the reference semantics. Elaborates the crate's exec
//!   code and evaluates `fn(args)` with the kernel evaluator; prints the
//!   value as JSON, never a verdict.
//! * `sandblaster profile <crate-dir|root.rs> --entry <fn> --fixtures <dir|manifest>
//!   [--fixtures <dir|manifest>…] --args <field,…> [--out <file>] [--append]
//!   [--target <arch>]` — the profile (optimizer design §10.4): evaluates
//!   `fn` with the reference evaluator on every fixture of the directories or
//!   split manifests (JSON objects; the named hex-string fields are the
//!   arguments, in order; a manifest is a `.txt` file with one fixture path
//!   per line, so the profile is recorded on a profile half and the benchmark
//!   times the other, `Profile::check_timed`)
//!   and records the argument values every loop head is entered with. A
//!   stage tool: it states no verdict. Writes `PROFILE.json` next to the DSL
//!   root's directory or `--out`; `--append` merges into the existing file
//!   (one entry per root, e.g. QMDB's production and N = 1 roots). The
//!   crate path reads that file as an input of the checked crate
//!   (`driver::Checked::profile`): it changes which loop summaries the
//!   optimizer tries, never what is admitted.
//!
//! Every prover call is bounded by its step budget, a per-goal deadline
//! (`SANDBLASTER_GOAL_TIMEOUT_MS`, default 30 s) and the memory soft limit
//! (`SANDBLASTER_MEM_LIMIT_GB`); a tripped safety net fails the command.
//!
//! A crate directory is resolved to its DSL root by, in order: the string
//! literal passed to `sandblaster::build::compile(..)` in `build.rs`,
//! `sandblaster/mod.rs`, `mod.rs`. `--target` accepts `aarch64`, `x86_64` or a
//! triple starting with one of them (default: the host).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sandblaster_front::driver::{self, LockUse};
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

fn usage() -> ExitCode {
    eprintln!("usage: sandblaster <check|emit|report> <crate-dir|root.rs> [--target aarch64|x86_64]");
    eprintln!("       sandblaster eval <crate-dir|root.rs> <fn> <args-json> [--target aarch64|x86_64]");
    eprintln!("       sandblaster spec <crate-dir|root.rs> [--accept [ITEM...] [--equivalent-only] | --diff <rev-or-path> | --preview <file>] [--target aarch64|x86_64]");
    eprintln!("       sandblaster coverage <crate-dir|root.rs> [--json] [--no-sheet] [--mutants-max N] [--time-budget SECS] [--only ITEM...] [--target aarch64|x86_64]");
    eprintln!("       sandblaster profile <crate-dir|root.rs> --entry <fn> --fixtures <dir|manifest>... --args <field,...> [--out <file>] [--append] [--target aarch64|x86_64]");
    eprintln!("       sandblaster conform <crate-dir|root.rs> --manifest-dir <host-crate-dir> --work-dir <dir> [--target aarch64|x86_64]");
    ExitCode::from(2)
}

/// Finds the DSL root for a crate directory or file argument.
pub fn find_root(arg: &Path) -> Result<PathBuf, String> {
    if arg.is_file() {
        return Ok(arg.to_path_buf());
    }
    if !arg.is_dir() {
        return Err(format!("`{}` is neither a file nor a directory", arg.display()));
    }
    if let Ok(b) = std::fs::read_to_string(arg.join("build.rs"))
        && let Some(i) = b.find("compile(")
    {
        let rest = &b[i + "compile(".len()..];
        if let Some(start) = rest.find('"')
            && let Some(end) = rest[start + 1..].find('"')
        {
            let rel = &rest[start + 1..start + 1 + end];
            let p = arg.join(rel);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    for cand in ["sandblaster/mod.rs", "mod.rs"] {
        let p = arg.join(cand);
        if p.is_file() {
            return Ok(p);
        }
    }
    Err(format!("no DSL root found in `{}` (expected build.rs with sandblaster::build::compile(\"..\"), sandblaster/mod.rs or mod.rs)", arg.display()))
}

fn main() -> ExitCode {
    // resource safety: cap this process's heap (SANDBLASTER_MEM_LIMIT_GB; the
    // counting allocator of sandblaster-memguard is linked through the front end)
    sandblaster_front::memguard::init_from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut positional: Vec<String> = Vec::new();
    let mut target = TargetInfo::host();
    let mut spec = SpecArgs::default();
    let mut cov = CoverageArgs::default();
    let mut prof = ProfileArgs::default();
    let mut conform_dirs: (Option<PathBuf>, Option<PathBuf>) = (None, None);
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => cov.json = true,
            "--no-sheet" => cov.no_sheet = true,
            "--mutants-max" => {
                let Some(n) = it.next().and_then(|x| x.parse::<usize>().ok()) else { return usage() };
                cov.max = Some(n);
            }
            "--time-budget" => {
                let Some(n) = it.next().and_then(|x| x.parse::<u64>().ok()) else { return usage() };
                cov.time_budget = Some(n);
            }
            "--only" => {
                while let Some(item) = it.next_if(|x| !x.starts_with("--")) {
                    cov.only.push(item.clone());
                }
            }
            "--entry" | "--fixtures" | "--args" | "--out" => {
                let Some(v) = it.next() else { return usage() };
                match a.as_str() {
                    "--entry" => prof.entry = Some(v.clone()),
                    "--fixtures" => prof.fixtures.push(PathBuf::from(v)),
                    "--args" => prof.fields = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                    _ => prof.out = Some(PathBuf::from(v)),
                }
            }
            "--append" => prof.append = true,
            "--manifest-dir" | "--work-dir" => {
                let Some(v) = it.next() else { return usage() };
                if a == "--manifest-dir" {
                    conform_dirs.0 = Some(PathBuf::from(v));
                } else {
                    conform_dirs.1 = Some(PathBuf::from(v));
                }
            }
            "--accept" => {
                spec.accept = true;
                while let Some(item) = it.next_if(|x| !x.starts_with("--")) {
                    spec.items.push(item.clone());
                }
            }
            "--equivalent-only" => spec.equivalent_only = true,
            "--diff" => {
                let Some(r) = it.next() else { return usage() };
                spec.diff = Some(r.clone());
            }
            "--preview" => {
                let Some(f) = it.next() else { return usage() };
                spec.preview = Some(PathBuf::from(f));
            }
            "--target" => {
                let Some(t) = it.next() else { return usage() };
                match TargetInfo::from_name(t) {
                    Some(ti) => target = ti,
                    None => {
                        eprintln!("unknown target `{t}` (use aarch64 or x86_64)");
                        return ExitCode::from(2);
                    }
                }
            }
            "-h" | "--help" => return usage(),
            _ => positional.push(a.clone()),
        }
    }
    // `sandblaster spec --accept <crate-dir>`: the crate path came last
    if positional.len() == 1 && positional[0] == "spec" && !spec.items.is_empty() {
        positional.push(spec.items.remove(0));
    }
    let Some(cmd) = positional.first().cloned() else { return usage() };
    let expected = if cmd == "eval" { 4 } else { 2 };
    // `sandblaster coverage --only a b <crate-dir>`: the crate path came last
    if positional.len() == 1 && positional[0] == "coverage" && !cov.only.is_empty() {
        positional.push(cov.only.pop().expect("an item"));
    }
    if !matches!(cmd.as_str(), "check" | "emit" | "report" | "eval" | "spec" | "coverage" | "profile" | "conform") || positional.len() != expected {
        return usage();
    }
    if (cmd == "conform") != (conform_dirs.0.is_some() && conform_dirs.1.is_some()) && (cmd == "conform" || conform_dirs.0.is_some() || conform_dirs.1.is_some()) {
        eprintln!("error: `sandblaster conform` needs --manifest-dir and --work-dir, and they belong to it alone");
        return usage();
    }
    if cmd != "coverage" && cov.used() {
        eprintln!("error: --json, --no-sheet, --mutants-max, --time-budget and --only belong to `sandblaster coverage`");
        return usage();
    }
    if cmd != "profile" && (prof.entry.is_some() || !prof.fixtures.is_empty() || !prof.fields.is_empty() || prof.out.is_some() || prof.append) {
        eprintln!("error: --entry, --fixtures, --args, --out and --append belong to `sandblaster profile`");
        return usage();
    }
    if cmd == "profile" && (prof.entry.is_none() || prof.fixtures.is_empty() || prof.fields.is_empty()) {
        eprintln!("error: `sandblaster profile` needs --entry, --fixtures and --args");
        return usage();
    }
    if cmd != "spec" && (spec.accept || spec.equivalent_only || spec.diff.is_some() || spec.preview.is_some()) {
        eprintln!("error: --accept, --equivalent-only, --diff and --preview belong to `sandblaster spec`");
        return usage();
    }
    if spec.preview.is_some() && (spec.accept || spec.diff.is_some()) {
        eprintln!("error: `spec --preview <file>` writes the lock `--accept` would write to <file>; it takes neither --accept nor --diff");
        return usage();
    }
    if spec.equivalent_only && (!spec.accept || !spec.items.is_empty()) || (spec.accept && spec.diff.is_some()) {
        eprintln!("error: use `spec --accept [ITEM...]`, `spec --accept --equivalent-only` or `spec --diff <rev-or-path>`");
        return usage();
    }
    let root = match find_root(Path::new(&positional[1])) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let checked = driver::check(&root, &RealFs, &target);
    let rendered = checked.render();
    if !rendered.is_empty() {
        eprintln!("{rendered}");
    }
    if !checked.ok() {
        eprintln!("error: sandblaster: {} error(s) in the front end", checked.diags.error_count());
        if cmd == "check" {
            print!("{}", driver::summary(&checked));
        }
        return ExitCode::from(1);
    }
    let root_display = root.display().to_string();
    if let Some(p) = &checked.profile
        && let Err(e) = &p.parsed
    {
        eprintln!("warning[profile]: `{}` ignored: {e}", p.path.display());
    }
    if cmd == "profile" {
        // a stage tool: writes PROFILE.json, never a verdict
        return profile_command(&checked, &root, &prof);
    }
    if cmd == "eval" {
        // a stage tool: a value, never a verdict
        return match driver::stage::eval_json(&checked, &positional[2], &positional[3]) {
            Ok(v) => {
                println!("{v}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        };
    }
    if cmd == "spec" {
        return spec_command(&checked, &root, &root_display, &target, &spec);
    }
    if cmd == "conform" {
        // a stage tool: the lift conformance check of the in-place modules, never a verdict
        let (Some(manifest), Some(work)) = conform_dirs else { return usage() };
        let rustc = PathBuf::from(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()));
        let edition = sandblaster_front::conform::edition_of(&RealFs, &manifest).unwrap_or_else(|| "2021".into());
        let mut cfg = sandblaster_front::conform::Config::new(rustc, work, &edition, "sandblaster conform");
        cfg.manifest_dir = Some(manifest);
        cfg.cargo = PathBuf::from(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        return match driver::stage::conform_in_place(&checked, &cfg) {
            Ok(r) => {
                println!("{}", r.summary());
                println!("{}", r.json().render());
                for f in r.failures() {
                    eprintln!("error[lift-conformance]: {f}");
                }
                if r.passed() { ExitCode::SUCCESS } else { ExitCode::from(1) }
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        };
    }
    // the crate path: every gate, the optimizer, the round trip
    let b = driver::build_crate(&checked, LockUse::Enforce, &root_display);
    print_diags(&checked, &b.diagnostics());
    for w in b.optimizer_warnings() {
        eprintln!("warning[optimizer]: {w}");
    }
    if cmd == "coverage" {
        return coverage_command(&checked, &root_display, &cov, &b);
    }
    let code = |b: &driver::CrateBuild| if b.verdict.is_some() { ExitCode::SUCCESS } else { ExitCode::from(1) };
    match cmd.as_str() {
        "check" => {
            if b.verdict.is_none() {
                eprint!("{}", failure_line(&b, &checked, &root_display));
            }
            print!("{}", b.summary(&checked));
            code(&b)
        }
        "report" => {
            print!("{}", b.report);
            code(&b)
        }
        _ => match &b.verdict {
            Some(v) => {
                print!("{}", v.code());
                ExitCode::SUCCESS
            }
            None => {
                eprint!("{}", failure_line(&b, &checked, &root_display));
                eprintln!("error: not emitting code: no crate verdict (see above)");
                ExitCode::from(1)
            }
        },
    }
}

/// The closing line(s) of a crate build without a verdict (the diagnostics
/// themselves were printed already).
fn failure_line(b: &driver::CrateBuild, checked: &driver::Checked, root_display: &str) -> String {
    let full = b.render_failure(checked, root_display);
    let diags = b.diagnostics().render(&checked.sm);
    full.strip_prefix(diags.as_str()).unwrap_or(&full).trim_start_matches('\n').to_string()
}

/// The options of `sandblaster coverage`.
#[derive(Default)]
struct CoverageArgs {
    json: bool,
    no_sheet: bool,
    max: Option<usize>,
    time_budget: Option<u64>,
    only: Vec<String>,
}

impl CoverageArgs {
    fn used(&self) -> bool {
        self.json || self.no_sheet || self.max.is_some() || self.time_budget.is_some() || !self.only.is_empty()
    }
}

/// `sandblaster coverage` (DESIGN.md §15.10; see the module docs): the
/// crate path ran already (`b`); this adds the exploration run.
fn coverage_command(checked: &driver::Checked, root_display: &str, a: &CoverageArgs, b: &driver::CrateBuild) -> ExitCode {
    use sandblaster_front::mutate;
    let krate = checked.krate.as_ref().expect("checked crate");
    // an `--only` item that names nothing would silently mutate nothing
    let unknown = mutate::unknown_only(krate, &a.only);
    if !unknown.is_empty() {
        for (o, close) in &unknown {
            let hint = if close.is_empty() { String::new() } else { format!(" (closest: {})", close.join(", ")) };
            eprintln!("error: sandblaster coverage: `--only {o}` names no function or constant of the crate{hint}");
        }
        return ExitCode::from(2);
    }
    // the exploration run: its options shape this report, never the gate
    let mut opts = mutate::MutateOptions::from_env();
    if let Some(n) = a.max {
        opts.max_mutants = n;
    }
    if let Some(t) = a.time_budget {
        opts.deadline = Some(std::time::Duration::from_secs(t));
    }
    opts.progress = true;
    opts.only = a.only.clone();
    let sheet = if a.no_sheet { None } else { b.surface.as_ref().map(|s| sandblaster_front::specdiff::sheet(root_display, s, &b.spec, &b.changes)) };
    let cov = mutate::coverage::coverage(krate, &checked.sm, &opts, sheet);
    if a.json {
        print!("{}", mutate::coverage::to_json(&cov).render());
    } else {
        print!("{}", mutate::coverage::render_text(&cov));
    }
    let mut d = sandblaster_front::diag::Diagnostics::new();
    mutate::spec15_gate_mutants(&cov.mutation, krate, &mut d);
    let n = d.list.len();
    if n > 0 {
        eprintln!("sandblaster coverage: the exploration run (not the gate) has {n} finding(s):");
        print_diags(checked, &d);
    }
    if !cov.mutation.baseline_verified {
        eprintln!("error: sandblaster coverage: the crate does not verify; the counterexample engine needs a verified baseline");
        for p in &cov.mutation.baseline_problems {
            eprintln!("  = {p}");
        }
    }
    match &b.verdict {
        Some(_) => ExitCode::SUCCESS,
        None => {
            eprint!("{}", failure_line(b, checked, root_display));
            ExitCode::from(1)
        }
    }
}

/// The options of `sandblaster spec`.
#[derive(Default)]
struct SpecArgs {
    accept: bool,
    items: Vec<String>,
    equivalent_only: bool,
    diff: Option<String>,
    /// `--preview <file>`: where to write the lock `--accept` would write.
    preview: Option<PathBuf>,
}

fn print_diags(checked: &sandblaster_front::driver::Checked, d: &sandblaster_front::diag::Diagnostics) {
    let r = d.render(&checked.sm);
    if !r.is_empty() {
        eprintln!("{r}");
    }
}

/// The proofs of one side of `sandblaster spec --diff` (exit code on
/// failure).
fn spec_verified(checked: &sandblaster_front::driver::Checked, run: &driver::stage::SpecRun) -> Result<(), ExitCode> {
    print_diags(checked, &run.v.diags);
    if !run.v.proofs_ok {
        eprintln!("error: sandblaster spec: the crate does not verify (see above); its specification surface is computed from a verified elaboration only");
        return Err(ExitCode::from(1));
    }
    Ok(())
}

/// The files of git revision `rev`, read on demand with `git show`: the
/// old side of `spec --diff <rev>`. The whole repository at `rev` is
/// visible (not only the DSL root directory), so everything the old
/// revision's loader asks for — its modules, `SPEC.lock`, and vector files
/// anywhere in the repository (`#[examples(file = "../../vectors/..")]`) —
/// comes from `rev`, at the same relative place.
struct GitRevFs {
    /// The repository's top directory (canonical).
    top: PathBuf,
    rev: String,
    /// Every blob path of `rev`, relative to `top`.
    blobs: std::collections::HashSet<PathBuf>,
    cache: std::cell::RefCell<std::collections::HashMap<PathBuf, Option<String>>>,
}

impl GitRevFs {
    fn git(args: &[&str], at: &Path) -> Result<Vec<u8>, String> {
        let out = std::process::Command::new("git").arg("-C").arg(at).args(args).output().map_err(|e| format!("cannot run git: {e}"))?;
        if !out.status.success() {
            return Err(format!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(out.stdout)
    }

    /// Opens revision `rev` of the repository containing `root` (the DSL
    /// root file); returns the provider and the old root path (the same
    /// place in the old tree).
    fn open(root: &Path, rev: &str) -> Result<(GitRevFs, PathBuf), String> {
        let dir = root.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let dir = std::fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let top = PathBuf::from(String::from_utf8_lossy(&Self::git(&["rev-parse", "--show-toplevel"], &dir)?).trim());
        let top = std::fs::canonicalize(&top).unwrap_or(top);
        let listing = Self::git(&["ls-tree", "-r", "--name-only", "-z", rev], &top)?;
        let blobs: std::collections::HashSet<PathBuf> = listing.split(|b| *b == 0).filter(|x| !x.is_empty()).map(|x| PathBuf::from(String::from_utf8_lossy(x).into_owned())).collect();
        let name = root.file_name().ok_or("the DSL root has no file name")?;
        let old_root = dir.join(name);
        let fs = GitRevFs { top, rev: rev.to_string(), blobs, cache: Default::default() };
        if fs.get(&old_root).is_none() {
            return Err(format!("git revision `{rev}` has no file `{}`", old_root.strip_prefix(&fs.top).unwrap_or(&old_root).display()));
        }
        Ok((fs, old_root))
    }

    /// The path of `p` relative to the repository top, if inside it.
    fn rel(&self, p: &Path) -> Option<PathBuf> {
        let abs = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir().ok()?.join(p) };
        let abs = sandblaster_front::loader::normalize(&abs);
        abs.strip_prefix(&self.top).ok().map(Path::to_path_buf)
    }

    fn get(&self, p: &Path) -> Option<String> {
        let rel = self.rel(p)?;
        if let Some(c) = self.cache.borrow().get(&rel) {
            return c.clone();
        }
        let text = if self.blobs.contains(&rel) {
            let spec = format!("{}:{}", self.rev, rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"));
            Self::git(&["show", &spec], &self.top).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
        } else {
            None
        };
        self.cache.borrow_mut().insert(rel, text.clone());
        text
    }
}

impl sandblaster_front::loader::FileProvider for GitRevFs {
    fn read(&self, path: &Path) -> std::io::Result<String> {
        self.get(path).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("not in git revision `{}`", self.rev)))
    }
    fn exists(&self, path: &Path) -> bool {
        self.get(path).is_some()
    }
}

fn spec_command(checked: &sandblaster_front::driver::Checked, root: &Path, root_display: &str, target: &TargetInfo, a: &SpecArgs) -> ExitCode {
    use sandblaster_front::lock::{self, Lock, Selection};
    use sandblaster_front::specdiff;
    if let Some(old_arg) = &a.diff {
        // the old revision, in its own elaboration (a separate kernel environment)
        let old_checked = if Path::new(old_arg).exists() {
            match find_root(Path::new(old_arg)) {
                Ok(r) => driver::check(&r, &RealFs, target),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            }
        } else {
            // a git revision: its files are read from git on demand, so the
            // old tree is complete wherever its inputs live
            match GitRevFs::open(root, old_arg) {
                Ok((fs, r)) => driver::check(&r, &fs, target),
                Err(e) => {
                    eprintln!("error: `{old_arg}` is neither a path nor a git revision of the DSL root: {e}");
                    return ExitCode::from(2);
                }
            }
        };
        if !old_checked.ok() {
            eprintln!("{}", old_checked.render());
            eprintln!("error: the old revision `{old_arg}` has front-end errors");
            return ExitCode::from(1);
        }
        let old_run = driver::stage::spec_run(&old_checked, &driver::stage::SpecBaseline::None, false);
        if let Err(c) = spec_verified(&old_checked, &old_run) {
            eprintln!("error: (the old revision `{old_arg}`)");
            return c;
        }
        let old_surface = old_run.surface.expect("verified");
        let entries: Vec<lock::LockEntry> = old_surface.items.iter().map(|i| lock::LockEntry::of(i, &old_surface.target)).collect();
        let run = driver::stage::spec_run(checked, &driver::stage::SpecBaseline::Old(entries), true);
        if let Err(c) = spec_verified(checked, &run) {
            return c;
        }
        println!("spec diff: `{old_arg}` -> `{root_display}` (target {})", target.arch.name());
        let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
        for c in &run.changes {
            let label = match c.class {
                Some(k) => format!("{} ({})", c.what.word(), k.word()),
                None => c.what.word().to_string(),
            };
            *counts.entry(c.class.map(|k| k.word().to_string()).unwrap_or_else(|| c.what.word().to_string())).or_default() += 1;
            println!("  {}: {label}", c.key);
            if !c.reason.is_empty() {
                println!("    why: {}", c.reason);
            }
            if !c.old.is_empty() {
                println!("    old: {}", c.old.join(" "));
            }
            if !c.new.is_empty() {
                println!("    new: {}", c.new.join(" "));
            }
        }
        let summary: Vec<String> = counts.iter().map(|(k, n)| format!("{n} {k}")).collect();
        println!("{} change(s){}", run.changes.len(), if summary.is_empty() { String::new() } else { format!(": {}", summary.join(", ")) });
        return ExitCode::SUCCESS;
    }
    let old_lock = match checked.spec_lock.as_deref().map(Lock::parse) {
        Some(Ok(l)) => Some(l),
        Some(Err(e)) if (a.accept && a.items.is_empty() && !a.equivalent_only) || a.preview.is_some() => {
            eprintln!("warning: the existing lock is malformed ({e}); --accept replaces it");
            None
        }
        Some(Err(e)) => {
            eprintln!("error: the lock at `{}` is malformed: {e}", checked.lock_path.display());
            if !a.accept {
                eprintln!("  = note: `sandblaster spec --accept` rewrites it after review");
            }
            return ExitCode::from(1);
        }
        None => None,
    };
    let lock_use = if a.accept { LockUse::Accepting } else { LockUse::Enforce };
    let b = driver::build_crate(checked, lock_use, root_display);
    print_diags(checked, &b.diagnostics());
    if let Some(file) = &a.preview {
        return preview_lock(checked, &b, old_lock.as_ref(), file);
    }
    if !a.accept {
        if let Some(surface) = &b.surface {
            print!("{}", specdiff::sheet(root_display, surface, &b.spec, &b.changes));
        }
        println!("{}: {}", lock_name(checked), b.spec.summary());
        return match &b.verdict {
            Some(_) => ExitCode::SUCCESS,
            None => {
                eprint!("{}", failure_line(&b, checked, root_display));
                ExitCode::from(1)
            }
        };
    }
    let (Some(permit), Some(surface)) = (&b.permit, &b.surface) else {
        eprint!("{}", failure_line(&b, checked, root_display));
        eprintln!("error: sandblaster spec --accept: not writing `{}`: a lock is written only for a crate that passes every gate but the lock (see above)", checked.lock_path.display());
        return ExitCode::from(1);
    };
    let sel = if a.equivalent_only {
        if old_lock.is_none() {
            eprintln!("error: --equivalent-only re-accepts kernel-proven-equivalent items of an existing lock; there is none at `{}`", checked.lock_path.display());
            return ExitCode::from(1);
        }
        let mut keys = specdiff::equivalent_keys(&b.changes);
        for c in b.changes.iter().filter(|c| !keys.contains(&c.key)) {
            println!("not accepted: {}: {}{}", c.key, c.what.word(), c.class.map(|k| format!(" ({}): {}", k.word(), c.reason)).unwrap_or_default());
        }
        keys.push("toolchain".into());
        Selection::Items(keys)
    } else if a.items.is_empty() {
        Selection::All
    } else {
        Selection::Items(a.items.clone())
    };
    let (new_lock, acc) = match lock::accept(permit, old_lock.as_ref(), surface, &sel) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::write(&checked.lock_path, new_lock.render()) {
        eprintln!("error: cannot write `{}`: {e}", checked.lock_path.display());
        return ExitCode::from(1);
    }
    for (w, ks) in [("added", &acc.added), ("changed", &acc.changed), ("removed", &acc.removed), ("restated", &acc.restated)] {
        for k in ks {
            println!("accepted ({w}): {k}");
        }
    }
    if acc.header {
        println!("accepted: the toolchain header");
    }
    let st = lock::compare(Some(&new_lock.render()), surface, &checked.lock_path.display().to_string());
    println!("wrote {} (root {}); {}: {}", checked.lock_path.display(), sandblaster_front::surface::hex(&new_lock.compute_root()), lock_name(checked), st.summary());
    ExitCode::SUCCESS
}

/// `sandblaster spec --preview <file>` (a review tool, no verdict): writes the
/// lock `spec --accept` would write for the computed surface to `file` —
/// never to the root's lock, which only `--accept` writes after every gate
/// passed (`lock::preview_accept`). The proofs must have gone through (the
/// surface is computed from the verified elaboration); the gates need not
/// (a lock that no longer matches fails the lock gate, and that is what a
/// preview is for).
fn preview_lock(checked: &driver::Checked, b: &driver::CrateBuild, old: Option<&sandblaster_front::lock::Lock>, file: &Path) -> ExitCode {
    use sandblaster_front::lock::{self, Selection};
    if sandblaster_front::loader::normalize(file) == sandblaster_front::loader::normalize(&checked.lock_path) || file.file_name().is_some_and(|n| n.to_string_lossy().starts_with("SPEC.") && n.to_string_lossy().ends_with(".lock")) {
        eprintln!("error: `spec --preview` never writes a lock file (`{}`): only `sandblaster spec --accept` does; pick another file name", file.display());
        return ExitCode::from(2);
    }
    let Some(surface) = &b.surface else {
        eprintln!("error: sandblaster spec --preview: the specification surface was not computed ({}); nothing written", b.spec.summary());
        return ExitCode::from(1);
    };
    let (new_lock, acc) = match lock::preview_accept(old, surface, &Selection::All) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let text = new_lock.render();
    if let Err(e) = std::fs::write(file, &text) {
        eprintln!("error: cannot write `{}`: {e}", file.display());
        return ExitCode::from(1);
    }
    let old_items = old.map(|l| l.entries_for(&surface.target).count());
    println!(
        "preview of {} for target {}: {} item(s) (the lock now: {}), {} proof internal(s) not locked; {} added, {} changed, {} removed, {} restated; root {}; written to {} (not the lock)",
        checked.lock_path.display(),
        surface.target,
        surface.items.len(),
        old_items.map(|n| format!("{n} item(s)")).unwrap_or_else(|| "missing or malformed".into()),
        surface.internal.len(),
        acc.added.len(),
        acc.changed.len(),
        acc.removed.len(),
        acc.restated.len(),
        sandblaster_front::surface::hex(&new_lock.compute_root()),
        file.display()
    );
    ExitCode::SUCCESS
}

/// `sandblaster profile` arguments.
#[derive(Default)]
struct ProfileArgs {
    entry: Option<String>,
    fixtures: Vec<PathBuf>,
    fields: Vec<String>,
    out: Option<PathBuf>,
    append: bool,
}

/// `sandblaster profile` (see the module docs).
fn profile_command(checked: &driver::Checked, root: &Path, a: &ProfileArgs) -> ExitCode {
    use sandblaster_front::opt::cost::profile::{self, Profile};
    let entry = a.entry.as_deref().unwrap_or_default();
    // paths in the file are relative to the file's directory when inside it
    let out = match &a.out {
        Some(o) => o.clone(),
        None => match root.parent().and_then(|d| d.parent()) {
            Some(d) => d.join("PROFILE.json"),
            None => {
                eprintln!("error: no directory for PROFILE.json (use --out)");
                return ExitCode::from(2);
            }
        },
    };
    let base = out.parent().filter(|p| !p.as_os_str().is_empty()).map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    let rel = |p: &Path| -> String {
        let abs = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let b = std::fs::canonicalize(&base).unwrap_or_else(|_| base.clone());
        abs.strip_prefix(&b).map(|r| r.display().to_string()).unwrap_or_else(|_| p.display().to_string())
    };
    let t0 = std::time::Instant::now();
    let mut p = match profile::profile_crate(checked, &rel(root), entry, &a.fixtures, &a.fields) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    for e in &mut p.entries {
        e.corpora = a.fixtures.iter().map(|f| rel(f)).collect();
    }
    if a.append
        && let Ok(text) = std::fs::read_to_string(&out)
    {
        match Profile::parse(&text) {
            Ok(mut old) => {
                // a re-run of the same root replaces its entry
                old.merge(p);
                p = old;
            }
            Err(e) => {
                eprintln!("error: `{}`: {e}", out.display());
                return ExitCode::from(1);
            }
        }
    }
    if let Err(e) = std::fs::write(&out, p.to_json()) {
        eprintln!("error: cannot write `{}`: {e}", out.display());
        return ExitCode::from(1);
    }
    for e in &p.entries {
        for (l, (calls, samples)) in &e.loops {
            eprintln!("profile: {} {l}: {calls} call(s), {} distinct argument vector(s)", e.root, samples.len());
        }
    }
    eprintln!("profile: wrote `{}` ({:.1?})", out.display(), t0.elapsed());
    ExitCode::SUCCESS
}

/// The file name of the root's lock (`SPEC.lock`, `SPEC.n1.lock`, …).
fn lock_name(checked: &driver::Checked) -> String {
    checked.lock_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "SPEC.lock".into())
}
