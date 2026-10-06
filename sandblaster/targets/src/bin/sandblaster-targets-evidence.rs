//! Regenerates the evidence record `evidence/<arch>.json` for the architecture
//! it is compiled for (DESIGN.md §9.2 "Validation (fail closed)").
//!
//! ```text
//! # aarch64, native (writes evidence/aarch64.json):
//! CARGO_TARGET_DIR=target/targets cargo run --release -p sandblaster-targets \
//!     --bin sandblaster-targets-evidence
//! # x86_64 under Rosetta 2 (writes evidence/x86_64.json):
//! CARGO_TARGET_DIR=target/targets cargo run --release -p sandblaster-targets \
//!     --target x86_64-apple-darwin --bin sandblaster-targets-evidence
//! # verify that the committed records match the current model sources:
//! ... --bin sandblaster-targets-evidence -- --check
//! # re-run only the kernel cross-checks of the core-text models (any host;
//! # updates the `core` records of BOTH evidence files, or with `--arch A` only
//! # those of architecture A; hardware records untouched):
//! CARGO_TARGET_DIR=target/targets cargo run --release -p sandblaster-targets --features kernel \
//!     --bin sandblaster-targets-evidence -- --core-only
//! ```
//!
//! Options: `--count N` random cases per model (default 10^7, the §9.2
//! threshold; smaller counts are recorded but do not make a model
//! `validated`), `--seed S` base seed, `--out PATH` output file, `--check`,
//! `--core-only`, `--kernel-count N` random cases per model of the kernel
//! cross-check (default 1000, the threshold), `--threads N` kernel worker
//! threads (default: available parallelism, at most 16).
//!
//! Per-CPU evidence (schema 3, design §19.1; used by `tools/host-kit`):
//!
//! * every hardware result is recorded under the campaign CPU's key (CPUID
//!   vendor/family/model/stepping + microcode, `+executor` if emulated), and
//!   a run **merges** into the existing record (`--merge PATH`; default: the
//!   output file if it exists, else the committed record; `--no-merge` for
//!   a fresh file): other CPUs' entries are kept, this CPU's replaced;
//! * on x86_64 the full campaign also runs the **known-answer tests** of the
//!   feature-only scalar sets (LZCNT, BMI1, BMI2, POPCNT;
//!   `evidence::kat`), `--kat-count N` random cases each (default 10^6);
//!   `--kat-only` runs just them (into the `--out`/committed record), and
//!   `--kat-force` adds a diagnostic run of `lzcnt`/`tzcnt` on a CPU that does
//!   not report them (they then execute as `bsr`/`bsf`; recorded as
//!   `diagnostic`, never as evidence);
//! * the executor is probed (`native`, `rosetta2`, or a detected emulator:
//!   `qemu-tcg`, `sde`, `valgrind`, `dynamorio`); `--executor NAME` records
//!   the run under a non-validating name the probe cannot see (e.g.
//!   `emulated` under QEMU user mode). It can only downgrade: `native` or
//!   `rosetta2` are accepted only when they equal the probe, and only those
//!   two ever validate a model;
//! * `--merge-files OUT A B ...` merges whole records (one kit output per
//!   host) into OUT: every CPU's entries are kept, a CPU's own newer
//!   campaign supersedes an older carried copy, and a same-CPU
//!   disagreement, or one that would drop a recorded failure, is refused
//!   (nothing written); OUT may be one of the inputs;
//! * `--cpu` prints the probed CPU identification as JSON;
//! * `--check-file PATH [--json]` validates any evidence file (the kit's
//!   output) and prints every model's verdict overall and per CPU, and the
//!   KAT verdicts (`--json`: one machine-readable object); exit 1 if it does
//!   not parse or is stale;
//! * `--record-set --set NAME --features A,B,.. --suite SUITE --cases N
//!   --mismatches M [--source TEXT] [--out PATH]` records one host run of a
//!   feature-only variant set's clones (`evidence::SetRecord`, the host
//!   kit's `sets` stage) under this machine's CPU key: `diagnostic` when
//!   the CPU does not report every feature of the set (the run forced it;
//!   never evidence), else `passed`/`failed`/`skipped`;
//! * `--kat-list` prints each KAT with its feature and instructions (the host
//!   kit checks them on the disassembly of `sandblaster_kat_<name>`).
//!
//! The core records (kernel cross-checks of `core/<arch>.core`, DESIGN.md
//! §9.2) are produced when the binary is built with `--features kernel`: a
//! full run then also runs the kernel campaign, and `--core-only` runs only
//! it. Without the feature a full run carries the existing core records over
//! (they stay valid only while the core text is unchanged).
//!
//! The campaign runs every model of the architecture against its real
//! intrinsic (features detected at run time; absent ones are recorded as
//! skipped), the FIPS 180-4 consistency properties relevant to the
//! architecture, the reference consistency of the 256/512-bit x86 models
//! (`consistency::x86_wide_models`; with it a model whose feature is absent
//! is `pending-hardware`, like SHA-NI), and the whole-compression hardware
//! checks; it writes the
//! record even if something failed (the failure is recorded, fail closed) and
//! then exits with status 1. After the outcomes it prints the wall time of
//! each model's hardware campaign (`time NAME SECONDS s`, registry order; a
//! diagnostic, not part of the record).

#[path = "evidence/kat_hw.rs"]
mod kat_hw;

use sandblaster_targets::consistency;
use sandblaster_targets::diff::{Config, Outcome};
use sandblaster_targets::evidence::{self, Machine, Validation, cpu, kat};
use sandblaster_targets::hw;
use sandblaster_targets::json::{self, Json};
use sandblaster_targets::registry::Arch;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

fn usage() -> ! {
    eprintln!(
        "usage: sandblaster-targets-evidence [--count N] [--seed S] [--out PATH] [--merge PATH | --no-merge] \
         [--kat-count N] [--kat-force] [--kat-only] [--executor NAME]\n       \
         sandblaster-targets-evidence --check | --core-only [--arch A] | [--executor NAME] --cpu | --check-file PATH [--json]\n       \
         sandblaster-targets-evidence --merge-files OUT A B ...\n       \
         sandblaster-targets-evidence --record-set --set NAME --features A,B --suite S --cases N --mismatches M [--source TEXT] [--out PATH] [--executor NAME]"
    );
    std::process::exit(2);
}

/// The probed machine, with the `--executor` override applied (exits with
/// status 2 if the override is refused).
fn probe_machine(executor: Option<&str>) -> Machine {
    let mut machine = Machine::probe(kat_hw::all_features(hw::current::detected_features()));
    if let Some(e) = executor
        && let Err(err) = machine.set_executor(e)
    {
        eprintln!("--executor: {err}");
        std::process::exit(2);
    }
    machine
}

/// `--cpu`: the probed CPU identification (the evidence key) as JSON.
fn print_cpu(executor: Option<&str>) -> ExitCode {
    let machine = probe_machine(executor);
    let uarch = machine.cpu.as_ref().map_or("unknown".to_string(), cpu::uarch_name);
    let doc = Json::obj([
        ("arch", Json::str(Arch::current().map_or("unknown", Arch::name))),
        ("cpu_key", Json::str(machine.cpu_key())),
        ("uarch", Json::str(uarch)),
        ("executor", Json::str(machine.executor.clone())),
        ("cpu_brand_string", Json::str(machine.cpu_brand_string.clone())),
        ("os", Json::str(machine.os.clone())),
        ("rustc", Json::str(machine.rustc.clone())),
        ("target", Json::str(machine.target.clone())),
        ("cpu", machine.cpu.as_ref().map_or(Json::Null, cpu::CpuId::to_json)),
        (
            "detected_features",
            Json::Obj(machine.detected_features.iter().map(|(f, b)| (f.clone(), Json::Bool(*b))).collect()),
        ),
    ]);
    print!("{}", doc.to_pretty());
    ExitCode::SUCCESS
}

fn verdict_str(v: &Validation) -> String {
    match v {
        Validation::Validated { executor } => format!("validated ({executor})"),
        Validation::PendingHardware => "pending-hardware".into(),
        Validation::Missing(r) => format!("missing: {r}"),
    }
}

/// `--check-file PATH [--json]`: validate an evidence file and print the
/// verdicts (overall, per CPU, KATs). Exit 1 if it does not parse or is stale.
fn check_file(path: &Path, as_json: bool) -> ExitCode {
    let file = match evidence::load_path(path, None) {
        Ok(f) => f,
        Err(e) => {
            if as_json {
                print!("{}", Json::obj([("ok", Json::Bool(false)), ("error", Json::str(e))]).to_pretty());
            } else {
                eprintln!("{e}");
            }
            return ExitCode::FAILURE;
        }
    };
    let stale = evidence::stale(&file);
    let models: Vec<(String, Json)> = file
        .arch
        .models()
        .iter()
        .map(|m| {
            let per_host: Vec<(String, Json)> = file
                .hosts
                .iter()
                .map(|h| (h.cpu_key.clone(), Json::str(verdict_str(&evidence::validation_on(&file, m, &h.cpu_key)))))
                .collect();
            (
                m.name.to_string(),
                Json::obj([
                    ("features", Json::Arr(m.features.iter().map(|f| Json::str(*f)).collect())),
                    ("verdict", Json::str(verdict_str(&evidence::validation_in(&file, m)))),
                    ("per_host", Json::Obj(per_host)),
                ]),
            )
        })
        .collect();
    let kats: Vec<(String, Json)> = kat::FEATURES
        .iter()
        .map(|f| {
            (
                f.to_string(),
                match evidence::kat_verdict(&file, f) {
                    Ok(keys) => Json::obj([("passed", Json::Bool(true)), ("cpus", Json::Arr(keys.into_iter().map(Json::str).collect()))]),
                    Err(e) => Json::obj([("passed", Json::Bool(false)), ("reason", Json::str(e))]),
                },
            )
        })
        .collect();
    // the recorded feature-only sets, each as it was recorded (name and
    // feature closure: the optimizer asks for the set it defines now)
    let mut set_defs: Vec<(String, Vec<String>)> = Vec::new();
    if let Ok(doc) = std::fs::read_to_string(path).map_err(|e| e.to_string()).and_then(|t| json::parse(&t).map_err(|e| e.to_string())) {
        for r in doc.get("sets").and_then(Json::as_array).unwrap_or(&[]) {
            let name = r.get("set").and_then(Json::as_str).unwrap_or("").to_string();
            let fs: Vec<String> = r.get("features").and_then(Json::as_array).unwrap_or(&[]).iter().filter_map(Json::as_str).map(str::to_string).collect();
            if !set_defs.contains(&(name.clone(), fs.clone())) {
                set_defs.push((name, fs));
            }
        }
    }
    let sets: Vec<(String, Json)> = set_defs
        .iter()
        .map(|(name, fs)| {
            let v = match evidence::set_verdict_in(&file, name, fs) {
                evidence::SetVerdict::Validated { cpus } => Json::obj([("validated", Json::Bool(true)), ("cpus", Json::Arr(cpus.into_iter().map(Json::str).collect()))]),
                evidence::SetVerdict::Missing(r) => Json::obj([("validated", Json::Bool(false)), ("reason", Json::str(r))]),
            };
            (name.clone(), v)
        })
        .collect();
    let ok = stale.is_empty();
    if as_json {
        let doc = Json::obj([
            ("ok", Json::Bool(ok)),
            ("path", Json::str(path.display().to_string())),
            ("arch", Json::str(file.arch.name())),
            ("cpu_key", Json::str(file.cpu_key.clone())),
            ("kat_hash", Json::str(kat::kat_hash())),
            ("stale", Json::Arr(stale.iter().map(|s| Json::str(s.clone())).collect())),
            (
                "hosts",
                Json::Arr(
                    file.hosts
                        .iter()
                        .map(|h| {
                            Json::obj([
                                ("cpu_key", Json::str(h.cpu_key.clone())),
                                ("cpu_brand_string", Json::str(h.cpu_brand_string.clone())),
                                ("executor", Json::str(h.executor.clone())),
                                ("date", Json::str(h.date.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("models", Json::Obj(models)),
            ("kats", Json::Obj(kats)),
            ("sets", Json::Obj(sets)),
        ]);
        print!("{}", doc.to_pretty());
    } else {
        println!("{}: {} ({} hosts, latest {})", path.display(), if ok { "current" } else { "STALE" }, file.hosts.len(), file.cpu_key);
        for s in &stale {
            println!("  stale: {s}");
        }
        for (name, j) in &models {
            println!("  {:<24} {}", name, j.get("verdict").and_then(Json::as_str).unwrap_or(""));
        }
        for (f, j) in &kats {
            println!("  KAT {:<8} {}", f, if j.get("passed").and_then(Json::as_bool) == Some(true) { "passed" } else { "not evidenced" });
        }
        for (name, j) in &sets {
            println!("  set {:<24} {}", name, if j.get("validated").and_then(Json::as_bool) == Some(true) { "validated".to_string() } else { format!("not evidenced ({})", j.get("reason").and_then(Json::as_str).unwrap_or("")) });
        }
    }
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// The earlier record a campaign merges into: `--merge PATH`, else the
/// output file if it exists, else the committed record.
fn merge_source(explicit: Option<&Path>, out: &Path, arch: Arch) -> Option<(PathBuf, Json)> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None if out.exists() => out.to_path_buf(),
        None => evidence::evidence_path(arch),
    };
    let doc = std::fs::read_to_string(&path).ok().and_then(|t| json::parse(&t).ok())?;
    Some((path, doc))
}

/// Drop the `legacy:` host entries of `old` that describe this very machine
/// (a schema-2 record of the same CPU and executor), so re-running on the
/// machine that produced a schema-2 record does not list it twice.
fn without_own_legacy(mut old: Json, machine: &Machine) -> Json {
    let own = evidence::legacy_key(&machine.cpu_brand_string, &machine.executor);
    let is_v2 = old.get("hosts").is_none();
    let same = old.get("machine").and_then(|m| m.get("cpu_brand_string")).and_then(Json::as_str) == Some(machine.cpu_brand_string.as_str())
        && old.get("machine").and_then(|m| m.get("executor")).and_then(Json::as_str) == Some(machine.executor.as_str());
    if is_v2 && same {
        // Nothing of the schema-2 campaign survives except its core records.
        if let Json::Obj(members) = &mut old {
            members.retain(|(k, _)| k != "models" && k != "machine");
        }
        return old;
    }
    let strip = |arr: &mut Vec<Json>| arr.retain(|h| h.get("cpu_key").and_then(Json::as_str) != Some(own.as_str()));
    if let Json::Obj(members) = &mut old {
        for (k, v) in members.iter_mut() {
            match (k.as_str(), v) {
                ("hosts" | "kats", Json::Arr(a)) => strip(a),
                ("models", Json::Arr(ms)) => {
                    for m in ms {
                        if let Json::Obj(mm) = m {
                            for (mk, mv) in mm.iter_mut() {
                                if let ("hosts", Json::Arr(a)) = (mk.as_str(), mv) {
                                    strip(a);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    old
}

/// `--merge-files OUT A B ...`: merge whole records ([`evidence::merge_files`])
/// and check the result.
fn merge_files(out: &Path, inputs: &[PathBuf]) -> ExitCode {
    let mut docs = Vec::new();
    for p in inputs {
        match std::fs::read_to_string(p).map_err(|e| e.to_string()).and_then(|t| json::parse(&t).map_err(|e| e.to_string())) {
            Ok(d) => docs.push(d),
            Err(e) => {
                eprintln!("{}: {e}", p.display());
                return ExitCode::FAILURE;
            }
        }
    }
    let mut merged = docs[0].clone();
    for (p, d) in inputs.iter().zip(&docs).skip(1) {
        match evidence::merge_files(&mut merged, d) {
            Ok(notes) => {
                for n in notes {
                    println!("  {}: {n}", p.display());
                }
            }
            Err(conflicts) => {
                eprintln!("cannot merge {} (nothing written):", p.display());
                for c in conflicts {
                    eprintln!("  {c}");
                }
                return ExitCode::FAILURE;
            }
        }
    }
    if let Err(e) = evidence::parse(&merged.to_pretty()) {
        eprintln!("the merged record does not parse: {e} (nothing written)");
        return ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::write(out, merged.to_pretty()) {
        eprintln!("cannot write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }
    println!("merged {} records into {}", inputs.len(), out.display());
    check_file(out, false)
}

/// One set run to record (`--record-set`).
struct SetRun {
    set: String,
    features: Vec<String>,
    suite: String,
    cases: u64,
    mismatches: u64,
    source: String,
}

/// `--record-set`: record one host run of a feature-only set's clones in
/// the `--out` (or committed) record (see `evidence::SetRecord`).
fn record_set(out: Option<PathBuf>, run: &SetRun, executor: Option<&str>) -> ExitCode {
    let Some(arch) = Arch::current() else {
        eprintln!("no target models for this architecture");
        return ExitCode::FAILURE;
    };
    let path = out.unwrap_or_else(|| evidence::evidence_path(arch));
    let mut doc = match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|t| json::parse(&t).map_err(|e| e.to_string())) {
        Ok(d) if d.get("hosts").is_some() => d,
        Ok(_) => {
            eprintln!("{}: not a schema-3 record", path.display());
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    if run.set.is_empty() || run.features.is_empty() || run.suite.is_empty() {
        usage();
    }
    let machine = probe_machine(executor);
    let entry = evidence::set_run_json(&machine, &run.set, &run.features, &run.suite, run.cases, run.mismatches, &run.source);
    let status = entry.get("status").and_then(Json::as_str).unwrap_or("").to_string();
    evidence::with_set_run(&mut doc, entry);
    if let Err(e) = std::fs::write(&path, doc.to_pretty()) {
        eprintln!("cannot write {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    println!("set {} {}: {} ({} cases, {} mismatches) on {} recorded in {}", run.set, run.suite, status, run.cases, run.mismatches, machine.cpu_key(), path.display());
    if status == "failed" { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

/// `--kat-only`: run the KATs and record them in the `--out` (or committed)
/// record.
fn kat_only(out: Option<PathBuf>, kcfg: &Config, force: bool, executor: Option<&str>) -> ExitCode {
    let Some(arch) = Arch::current() else {
        eprintln!("no target models for this architecture");
        return ExitCode::FAILURE;
    };
    let path = out.unwrap_or_else(|| evidence::evidence_path(arch));
    let mut doc = match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|t| json::parse(&t).map_err(|e| e.to_string())) {
        Ok(d) if d.get("hosts").is_some() => d,
        Ok(_) => {
            eprintln!("{}: not a schema-3 record (run the full campaign first)", path.display());
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let machine = probe_machine(executor);
    let kats = kat_hw::run(kcfg, force);
    let mut failed = false;
    for k in &kats {
        println!("{}", kat_hw::summary(k));
        failed |= k.status() == "failed";
    }
    evidence::with_kats(&mut doc, &kats, &machine.cpu_key());
    if let Err(e) = std::fs::write(&path, doc.to_pretty()) {
        eprintln!("cannot write {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    println!("recorded {} KATs in {}", kats.len(), path.display());
    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

fn parse_u64(s: &str) -> u64 {
    let s = s.replace('_', "");
    let v = if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse()
    };
    v.unwrap_or_else(|_| usage())
}

fn check() -> ExitCode {
    let mut ok = true;
    for arch in [Arch::Aarch64, Arch::X86_64] {
        match evidence::load(arch) {
            Ok(file) => {
                let stale = evidence::stale(&file);
                if stale.is_empty() {
                    println!(
                        "{}: current ({} records, {} on {}, {})",
                        arch.name(),
                        file.records.len(),
                        file.cpu_brand_string,
                        file.executor,
                        file.date
                    );
                    for m in arch.models() {
                        let core = file
                            .records
                            .iter()
                            .find(|r| r.name == m.name)
                            .and_then(|r| r.core.as_ref())
                            .map_or("no core record".to_string(), |c| {
                                format!("{} kernel-cross-checked: {} random + {} corner, {} mismatches", c.global, c.random_cases, c.corner_cases, c.mismatches)
                            });
                        println!("  {:<24} {:?}; {core}", m.name, evidence::validation_in(&file, m));
                    }
                } else {
                    ok = false;
                    println!("{}: STALE", arch.name());
                    for s in stale {
                        println!("  {s}");
                    }
                }
            }
            Err(e) => {
                ok = false;
                println!("{}: {e}", arch.name());
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Options of the kernel campaign.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "kernel"), allow(dead_code))]
struct KernelOpts {
    random_per_model: u64,
    threads: usize,
}

/// The kernel campaign: every core model of `archs` and the compression
/// checks. Returns (per-model outcomes, compositions, config).
#[cfg(feature = "kernel")]
fn kernel_campaign(opts: KernelOpts, archs: &[Arch]) -> (Vec<Outcome>, Vec<Outcome>, Config) {
    use sandblaster_targets::kernel;
    let cfg = Config {
        random_per_model: opts.random_per_model,
        seed: kernel::KERNEL_SEED,
    };
    let t = Instant::now();
    let outcomes = kernel::crosscheck_all(archs, &cfg, opts.threads);
    let compositions = kernel::compress_checks(
        &Config {
            random_per_model: kernel::EVIDENCE_RANDOM_PER_COMPRESSION,
            seed: kernel::KERNEL_SEED,
        },
        opts.threads,
    );
    eprintln!("kernel cross-checks: {:.1?}", t.elapsed());
    (outcomes, compositions, cfg)
}

/// `sha256:<hex>` of the kernel prelude text.
#[cfg(feature = "kernel")]
fn prelude_hash() -> String {
    let mut text = String::new();
    for (name, src) in sandblaster_kernel::PRELUDE_FILES {
        text.push_str(name);
        text.push('\n');
        text.push_str(src);
    }
    format!("sha256:{}", sandblaster_targets::fips::hex(&sandblaster_targets::fips::sha256(text.as_bytes())))
}

/// Every model's hardware campaign, as `hw::current::run_all` (registry
/// order, one worker thread per available core), plus the wall time of each
/// model's campaign on its worker thread, in registry order.
fn run_all_timed(arch: Arch, cfg: &Config) -> (Vec<Outcome>, Vec<(String, f64)>) {
    let names: Vec<&str> = arch.models().iter().map(|m| m.name).collect();
    let times = std::sync::Mutex::new(Vec::with_capacity(names.len()));
    let outcomes = hw::run_parallel(&names, |name| {
        let t = Instant::now();
        let o = hw::current::run_model(name, cfg).unwrap_or_else(|| panic!("no campaign for model {name}"));
        times.lock().expect("timing lock").push((name.to_string(), t.elapsed().as_secs_f64()));
        o
    });
    let mut times = times.into_inner().expect("timing lock");
    times.sort_by_key(|(n, _)| names.iter().position(|m| m == n));
    (outcomes, times)
}

/// Print outcomes; `true` if one failed.
fn report(outcomes: &[&Outcome]) -> bool {
    let mut failed = false;
    for o in outcomes {
        println!("{}", o.summary());
        if o.skipped.is_none() && !o.passed() {
            failed = true;
            println!("    {}", o.first_mismatch.as_deref().unwrap_or("no cases"));
        }
    }
    failed
}

/// `--core-only [--arch A]`: re-run the kernel campaign and update the core
/// records of the committed evidence files in place (both architectures, or
/// only `A`).
#[cfg(feature = "kernel")]
fn core_only(opts: KernelOpts, archs: &[Arch]) -> ExitCode {
    let (outcomes, compositions, cfg) = kernel_campaign(opts, archs);
    let failed = report(&outcomes.iter().chain(&compositions).collect::<Vec<_>>());
    let machine = Machine::probe(Vec::new());
    let ph = prelude_hash();
    let campaign = evidence::CoreCampaign {
        outcomes: &outcomes,
        compositions: &compositions,
        machine: &machine,
        config: &cfg,
        prelude_hash: &ph,
    };
    for &arch in archs {
        let path = evidence::evidence_path(arch);
        let mut doc = match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|t| json::parse(&t).map_err(|e| e.to_string())) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{}: {e} (run the hardware campaign first)", path.display());
                return ExitCode::FAILURE;
            }
        };
        evidence::with_core(&mut doc, arch, &campaign);
        if let Err(e) = std::fs::write(&path, doc.to_pretty()) {
            eprintln!("cannot write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        println!("updated core records in {}", path.display());
    }
    if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

fn main() -> ExitCode {
    let mut cfg = Config::large();
    let mut out: Option<PathBuf> = None;
    let mut kopts = KernelOpts {
        random_per_model: 1000,
        // Kernel campaign worker threads (`--threads N` sets their number).
        threads: std::thread::available_parallelism().map_or(4, |n| n.get()).min(16),
    };
    let mut core_only_mode = false;
    let mut core_archs: Vec<Arch> = vec![Arch::Aarch64, Arch::X86_64];
    let mut kat_count: u64 = 1_000_000;
    let mut kat_force = false;
    let mut kat_only_mode = false;
    let mut merge: Option<PathBuf> = None;
    let mut no_merge = false;
    let mut check_path: Option<PathBuf> = None;
    let mut as_json = false;
    let mut executor: Option<String> = None;
    let mut cpu_mode = false;
    let mut record_set_mode = false;
    let mut set_run = SetRun { set: String::new(), features: Vec::new(), suite: String::new(), cases: 0, mismatches: 0, source: String::new() };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--count" => cfg.random_per_model = parse_u64(&args.next().unwrap_or_else(|| usage())),
            "--seed" => cfg.seed = parse_u64(&args.next().unwrap_or_else(|| usage())),
            "--out" => out = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--kernel-count" => kopts.random_per_model = parse_u64(&args.next().unwrap_or_else(|| usage())),
            "--threads" => kopts.threads = parse_u64(&args.next().unwrap_or_else(|| usage())) as usize,
            "--core-only" => core_only_mode = true,
            "--arch" => core_archs = vec![Arch::from_name(&args.next().unwrap_or_else(|| usage())).unwrap_or_else(|| usage())],
            "--check" => return check(),
            "--cpu" => cpu_mode = true,
            "--executor" => executor = Some(args.next().unwrap_or_else(|| usage())),
            "--merge-files" => {
                let rest: Vec<PathBuf> = args.by_ref().map(PathBuf::from).collect();
                if rest.len() < 3 {
                    usage();
                }
                return merge_files(&rest[0], &rest[1..]);
            }
            "--check-file" => check_path = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--json" => as_json = true,
            "--kat-list" => {
                for k in kat::KATS {
                    println!("{} {} {}", k.name, k.feature, k.instructions.join(","));
                }
                return ExitCode::SUCCESS;
            }
            "--kat-count" => kat_count = parse_u64(&args.next().unwrap_or_else(|| usage())),
            "--kat-force" => kat_force = true,
            "--kat-only" => kat_only_mode = true,
            "--record-set" => record_set_mode = true,
            "--set" => set_run.set = args.next().unwrap_or_else(|| usage()),
            "--features" => set_run.features = args.next().unwrap_or_else(|| usage()).split(',').filter(|f| !f.is_empty()).map(str::to_string).collect(),
            "--suite" => set_run.suite = args.next().unwrap_or_else(|| usage()),
            "--cases" => set_run.cases = parse_u64(&args.next().unwrap_or_else(|| usage())),
            "--mismatches" => set_run.mismatches = parse_u64(&args.next().unwrap_or_else(|| usage())),
            "--source" => set_run.source = args.next().unwrap_or_else(|| usage()),
            "--merge" => merge = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--no-merge" => no_merge = true,
            _ => usage(),
        }
    }
    if cpu_mode {
        return print_cpu(executor.as_deref());
    }
    if record_set_mode {
        return record_set(out, &set_run, executor.as_deref());
    }
    if let Some(p) = check_path {
        return check_file(&p, as_json);
    }
    let kcfg = Config { random_per_model: kat_count, seed: cfg.seed };
    if kat_only_mode {
        return kat_only(out, &kcfg, kat_force, executor.as_deref());
    }
    if core_only_mode {
        #[cfg(feature = "kernel")]
        return core_only(kopts, &core_archs);
        #[cfg(not(feature = "kernel"))]
        {
            eprintln!("--core-only needs the kernel: build with `--features kernel`");
            return ExitCode::FAILURE;
        }
    }
    let Some(arch) = Arch::current() else {
        eprintln!("no target models for this architecture");
        return ExitCode::FAILURE;
    };
    let out = out.unwrap_or_else(|| evidence::evidence_path(arch));
    let machine = probe_machine(executor.as_deref());
    eprintln!(
        "{} on {} ({}), CPU key {}, {}, {} build, {} random cases per model",
        arch.name(),
        machine.cpu_brand_string,
        machine.executor,
        machine.cpu_key(),
        machine.rustc,
        machine.profile,
        cfg.random_per_model
    );
    if machine.profile != "release" && cfg.random_per_model >= evidence::REQUIRED_RANDOM_CASES {
        eprintln!("note: debug build; the campaign will be slow (use --release)");
    }

    let t = Instant::now();
    let (hardware, model_times) = run_all_timed(arch, &cfg);
    let hardware_compositions = hw::current::run_compositions(&cfg);
    eprintln!("hardware campaigns: {:.1?}", t.elapsed());

    let t = Instant::now();
    let (prefixes, per_model) = match arch {
        Arch::Aarch64 => (
            ["sha2_", "compress_sha2"],
            consistency::aarch64_models(&cfg),
        ),
        Arch::X86_64 => {
            // SHA-NI: FIPS 180-4; the 256/512-bit models: their independent
            // references (the consistency evidence where the CPU lacks the feature).
            let mut v = consistency::x86_models(&cfg);
            v.extend(consistency::x86_wide_models(&cfg));
            (["shani_", "compress_shani"], v)
        }
    };
    let mut consistency_outcomes = per_model;
    consistency_outcomes.extend(
        consistency::compositions(&cfg)
            .into_iter()
            .filter(|o| prefixes.iter().any(|p| o.name.starts_with(p))),
    );
    eprintln!("consistency campaigns: {:.1?}", t.elapsed());

    let all: Vec<&Outcome> = hardware
        .iter()
        .chain(&hardware_compositions)
        .chain(&consistency_outcomes)
        .collect();
    let mut failed = report(&all);
    // Wall time of each model's hardware campaign (diagnostic only; not part
    // of the evidence record).
    for (name, secs) in &model_times {
        println!("time {name:<34} {secs:>8.3} s");
    }

    // Known-answer tests of the feature-only scalar sets (x86_64).
    let t = Instant::now();
    let kats = kat_hw::run(&kcfg, kat_force);
    for k in &kats {
        println!("{}", kat_hw::summary(k));
        failed |= k.status() == "failed";
    }
    if !kats.is_empty() {
        eprintln!("known-answer tests: {:.1?}", t.elapsed());
    }

    let mut doc = evidence::render(
        arch,
        &machine,
        &cfg,
        &hardware,
        &consistency_outcomes,
        &hardware_compositions,
    );
    evidence::with_kats(&mut doc, &kats, &machine.cpu_key());
    let old = if no_merge { None } else { merge_source(merge.as_deref(), &out, arch) };
    #[cfg(not(feature = "kernel"))]
    let _ = &core_archs;
    #[cfg(feature = "kernel")]
    {
        let (outcomes, compositions, kcfg) = kernel_campaign(kopts, &[Arch::Aarch64, Arch::X86_64]);
        failed |= report(&outcomes.iter().chain(&compositions).collect::<Vec<_>>());
        let ph = prelude_hash();
        let campaign = evidence::CoreCampaign {
            outcomes: &outcomes,
            compositions: &compositions,
            machine: &machine,
            config: &kcfg,
            prelude_hash: &ph,
        };
        evidence::with_core(&mut doc, arch, &campaign);
    }
    #[cfg(not(feature = "kernel"))]
    {
        let _ = kopts;
        // Carry from the merge source (the output file if it exists, else the
        // committed record), even with --no-merge.
        let source = old.clone().or_else(|| merge_source(merge.as_deref(), &out, arch));
        match &source {
            Some((path, old_doc)) => {
                evidence::carry_core(&mut doc, old_doc);
                eprintln!("core records carried over from {} (build with --features kernel to re-run them)", path.display());
            }
            None => eprintln!("no core records: build with --features kernel and run --core-only"),
        }
    }
    if let Some((path, old_doc)) = old {
        evidence::merge_hosts(&mut doc, &without_own_legacy(old_doc, &machine));
        eprintln!("merged the other CPUs' entries of {}", path.display());
    }
    if let Some(dir) = out.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(&out, doc.to_pretty()) {
        eprintln!("cannot write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }
    println!("wrote {}", out.display());
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
