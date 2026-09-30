//! The committed evidence records are well-formed and current (DESIGN.md
//! §9.2 "Validation (fail closed)").
//!
//! A model edited after its campaign makes its record stale, and this test
//! fails until the records are regenerated:
//!
//! ```text
//! CARGO_TARGET_DIR=target/targets cargo run --release -p sandblaster-targets --bin sandblaster-targets-evidence
//! CARGO_TARGET_DIR=target/targets cargo run --release -p sandblaster-targets --target x86_64-apple-darwin \
//!     --bin sandblaster-targets-evidence
//! ```
//!
//! A campaign merges into the record (its own CPU's entries replaced, every
//! other CPU's kept). The x86_64 record holds the Rosetta 2 campaign of the
//! dev Mac and the native Zen 5 campaign of AVX-512 host round 0
//! (`host-results/round0/evidence/x86_64.json`, integrated with
//! `sandblaster-targets-evidence --merge-files C C <host record>`; never copy a
//! host's record over this one), and the Zen 5 campaign of the 256/512-bit
//! models (`host-results/avx512-models/out/x86_64.json`, docs/avx512-models.md).

use sandblaster_targets::evidence::{self, Validation};
use sandblaster_targets::json::{self, Json};
use sandblaster_targets::registry::{self, Arch, ROUND0_X86_64};

const REGENERATE: &str = "regenerate with `cargo run --release -p sandblaster-targets --bin sandblaster-targets-evidence` \
     (add `--target x86_64-apple-darwin` for x86_64)";

#[test]
fn evidence_records_are_current() {
    for arch in [Arch::Aarch64, Arch::X86_64] {
        let file = evidence::load(arch).unwrap_or_else(|e| panic!("{e}; {REGENERATE}"));
        let stale = evidence::stale(&file);
        assert!(
            stale.is_empty(),
            "{} evidence is stale:\n{}\n{REGENERATE}",
            arch.name(),
            stale.join("\n")
        );
        assert!(
            !file.rustc.is_empty() && !file.cpu_brand_string.is_empty() && file.date.len() == 10
        );
    }
}

#[test]
fn aarch64_models_are_hardware_validated() {
    let file = evidence::load(Arch::Aarch64).unwrap_or_else(|e| panic!("{e}; {REGENERATE}"));
    assert_eq!(file.executor, "native");
    for m in Arch::Aarch64.models() {
        assert_eq!(
            evidence::validation_in(&file, m),
            Validation::Validated {
                executor: "native".into()
            },
            "{}",
            m.name
        );
        assert!(evidence::is_validated(Arch::Aarch64, m.name));
    }
}

/// The CPU of AVX-512 host round 0 (docs/avx512-round0.md): AWS c8a, AMD
/// EPYC 9R45 (Zen 5), CPUID family 0x1a model 0x02 stepping 1, microcode
/// `0xb002162`, run natively. Its campaign is the only SHA-NI hardware
/// evidence in the record.
const ZEN5: &str = "AuthenticAMD/1a-02-01/0xb002162";

/// Every x86_64 model is validated, the SHA-NI ones natively on the Zen 5
/// CPU only; the verdicts stay per CPU (DESIGN.md §9.2, design §19.1): the
/// Rosetta 2 host, which has no SHA-NI, keeps its `pending-hardware`
/// entries, and the SSE/SSSE3/SSE4.1 models are validated on both CPUs.
/// The 256/512-bit models (MODELS.md §10) have Zen 5 entries only
/// (`host-results/avx512-models/`, docs/avx512-models.md): validated there,
/// no verdict on the Rosetta 2 CPU, which never ran them (it has no AVX).
#[test]
fn x86_models_validated_and_sha_ni_native_on_zen5() {
    let file = evidence::load(Arch::X86_64).unwrap_or_else(|e| panic!("{e}; {REGENERATE}"));
    assert_eq!(file.schema, evidence::SCHEMA, "the round-0 campaign is merged (per-CPU record)");
    let zen5 = file.hosts.iter().find(|h| h.cpu_key == ZEN5).unwrap_or_else(|| panic!("no {ZEN5} host in {:?}", file.hosts));
    assert_eq!(zen5.executor, "native");
    assert!(zen5.cpu_brand_string.contains("EPYC 9R45"), "{}", zen5.cpu_brand_string);
    let cpu = zen5.cpu.as_ref().expect("CPUID identification of the Zen 5 host");
    assert_eq!((cpu.vendor.as_str(), cpu.family, cpu.model, cpu.stepping, cpu.microcode.as_deref()), ("AuthenticAMD", 0x1a, 0x02, 1, Some("0xb002162")));
    // the Rosetta 2 host of the original record is kept (merged, not copied over)
    let rosetta: Vec<&str> = file.hosts.iter().filter(|h| h.executor == "rosetta2").map(|h| h.cpu_key.as_str()).collect();
    assert!(!rosetta.is_empty(), "the Rosetta 2 entries were dropped: {:?}", file.hosts);
    let native = Validation::Validated { executor: "native".into() };
    for m in Arch::X86_64.models() {
        assert_eq!(evidence::validation_in(&file, m), native, "{}", m.name);
        assert_eq!(evidence::validation_on(&file, m, ZEN5), native, "{} on {ZEN5}", m.name);
        assert!(evidence::is_validated(Arch::X86_64, m.name), "{}", m.name);
        let rec = file.records.iter().find(|r| r.name == m.name).unwrap();
        let entry = rec.hosts.iter().find(|h| h.cpu_key == ZEN5).unwrap();
        assert!(entry.counts_as_validated() && entry.random_cases >= evidence::REQUIRED_RANDOM_CASES && entry.corner_cases > 0, "{}: {entry:?}", m.name);
        let wide = registry::X86_64[ROUND0_X86_64..].iter().any(|w| w.name == m.name);
        for key in &rosetta {
            let on = evidence::validation_on(&file, m, key);
            if wide {
                assert!(matches!(on, Validation::Missing(_)), "{} on {key}: {on:?}", m.name);
            } else if m.features.contains(&"sha") {
                // Rosetta 2 has no SHA-NI: only FIPS consistency evidence on
                // that CPU; the validation comes from the Zen 5 campaign.
                assert_eq!(on, Validation::PendingHardware, "{} on {key}", m.name);
            } else {
                assert_eq!(on, Validation::Validated { executor: "rosetta2".into() }, "{} on {key}", m.name);
            }
        }
    }
}

/// The SHA-NI verdict is gated per CPU and fails closed: it rests on the
/// Zen 5 entries alone (without them the models are `pending-hardware`
/// again), a failure recorded on any other CPU withdraws it, and the same
/// campaign recorded under an emulator never validates.
#[test]
fn sha_ni_validation_rests_on_the_zen5_entries_and_fails_closed() {
    let text = std::fs::read_to_string(evidence::evidence_path(Arch::X86_64)).unwrap();
    let sha: Vec<&str> = Arch::X86_64.models().iter().filter(|m| m.features.contains(&"sha")).map(|m| m.name).collect();
    assert_eq!(sha.len(), 3, "{sha:?}");
    let verdicts = |f: &evidence::EvidenceFile| -> Vec<Validation> {
        Arch::X86_64.models().iter().filter(|m| sha.contains(&m.name)).map(|m| evidence::validation_in(f, m)).collect()
    };
    // without the Zen 5 entries
    let without = edit_hosts(&text, |_, hosts| hosts.retain(|h| h.get("cpu_key").and_then(Json::as_str) != Some(ZEN5)));
    assert!(verdicts(&without).iter().all(|v| *v == Validation::PendingHardware), "{:?}", verdicts(&without));
    for m in Arch::X86_64.models()[..ROUND0_X86_64].iter().filter(|m| !sha.contains(&m.name)) {
        assert_eq!(evidence::validation_in(&without, m), Validation::Validated { executor: "rosetta2".into() }, "{}", m.name);
    }
    // ...and the 256/512-bit models have no evidence at all (fail closed).
    for m in &Arch::X86_64.models()[ROUND0_X86_64..] {
        assert!(matches!(evidence::validation_in(&without, m), Validation::Missing(_)), "{}", m.name);
    }
    // a failed SHA-NI campaign on another CPU (a model version the Zen 5 run validated)
    let failed = edit_hosts(&text, |name, hosts| {
        if sha.contains(&name) {
            let mut bad = hosts.iter().find(|h| h.get("cpu_key").and_then(Json::as_str) == Some(ZEN5)).unwrap().clone();
            set(&mut bad, "cpu_key", Json::str("GenuineIntel/6-8f-08/0x2b000603"));
            set(&mut bad, "status", Json::str("failed"));
            set(&mut bad, "mismatches", Json::uint(1));
            hosts.push(bad);
        }
    });
    assert!(verdicts(&failed).iter().all(|v| matches!(v, Validation::Missing(r) if r.contains("campaign failed"))), "{:?}", verdicts(&failed));
    // the Zen 5 entries recorded under an instruction emulator
    let emulated = edit_hosts(&text, |_, hosts| {
        for h in hosts.iter_mut().filter(|h| h.get("cpu_key").and_then(Json::as_str) == Some(ZEN5)) {
            set(h, "executor", Json::str("sde"));
        }
    });
    assert!(verdicts(&emulated).iter().all(|v| matches!(v, Validation::Missing(_))), "{:?}", verdicts(&emulated));
}

/// The committed x86_64 record with every model's `hosts` array edited by
/// `f(model name, hosts)`, parsed.
fn edit_hosts(text: &str, mut f: impl FnMut(&str, &mut Vec<Json>)) -> evidence::EvidenceFile {
    let mut doc = json::parse(text).unwrap();
    let Json::Obj(members) = &mut doc else { panic!("not an object") };
    let (_, Json::Arr(models)) = members.iter_mut().find(|(k, _)| k == "models").unwrap() else { panic!("no models") };
    for m in models.iter_mut() {
        let name = m.get("name").and_then(Json::as_str).unwrap().to_string();
        let Json::Obj(fields) = m else { panic!("model is not an object") };
        let (_, Json::Arr(hosts)) = fields.iter_mut().find(|(k, _)| k == "hosts").unwrap() else { panic!("{name}: no hosts") };
        f(&name, hosts);
    }
    evidence::parse(&doc.to_pretty()).unwrap()
}

fn set(obj: &mut Json, key: &str, value: Json) {
    let Json::Obj(fields) = obj else { panic!("not an object") };
    fields.iter_mut().find(|(k, _)| k == key).unwrap_or_else(|| panic!("no `{key}`")).1 = value;
}

#[test]
fn every_model_has_a_current_kernel_crosschecked_core_record() {
    // The chain hardware ↔ Rust model ↔ core model: every record carries the
    // hash of the model's core text as compiled now and a passing kernel
    // cross-check (≥ 1000 random cases, every immediate). Regenerate with
    // `cargo run --release -p sandblaster-targets --features kernel --bin sandblaster-targets-evidence -- --core-only`.
    for arch in [Arch::Aarch64, Arch::X86_64] {
        let file = evidence::load(arch).unwrap_or_else(|e| panic!("{e}; {REGENERATE}"));
        for m in arch.models() {
            let rec = file.records.iter().find(|r| r.name == m.name).unwrap();
            evidence::core_check(arch, rec, m).unwrap_or_else(|e| panic!("{e}"));
        }
    }
}

#[test]
fn unknown_models_are_not_validated() {
    assert!(!evidence::is_validated(Arch::Aarch64, "vsha512rq_u64"));
    assert!(!evidence::is_validated(Arch::Aarch64, "vsm3ss1q_u32"));
    assert!(!evidence::is_validated(Arch::X86_64, "_mm512_aesenc_epi128"));
    assert!(!evidence::is_validated(Arch::X86_64, "_mm512_clmulepi64_epi128"));
}

/// The 256/512-bit models: each has a native Zen 5 entry for its current
/// model hash with ≥ 10^7 random cases, corners and (for imm8 forms) every
/// immediate, and the record keeps the reference-consistency result the
/// campaign ran next to it.
#[test]
fn wide_models_have_native_zen5_campaigns() {
    let file = evidence::load(Arch::X86_64).unwrap_or_else(|e| panic!("{e}; {REGENERATE}"));
    let text = std::fs::read_to_string(evidence::evidence_path(Arch::X86_64)).unwrap();
    let doc = json::parse(&text).unwrap();
    let models = doc.get("models").and_then(Json::as_array).unwrap();
    for m in &registry::X86_64[ROUND0_X86_64..] {
        let rec = file.records.iter().find(|r| r.name == m.name).unwrap_or_else(|| panic!("no record for {}", m.name));
        let zen5 = rec.hosts.iter().find(|h| h.cpu_key == ZEN5).unwrap_or_else(|| panic!("{}: no {ZEN5} entry", m.name));
        assert!(zen5.counts_as_validated() && zen5.corner_cases > 0 && zen5.source_hash == evidence::model_hash(m), "{}: {zen5:?}", m.name);
        let j = models.iter().find(|x| x.get("name").and_then(Json::as_str) == Some(m.name)).unwrap();
        let hw = j.get("hardware").unwrap();
        let want_imms = m.immediates.as_ref().map(|r| format!("{}..={} (exhaustive)", r.start(), r.end()));
        assert_eq!(hw.get("immediates").and_then(Json::as_str).map(str::to_string), want_imms, "{}", m.name);
        let rc = j.get("reference_consistency").unwrap_or_else(|| panic!("{}: no reference_consistency", m.name));
        assert_eq!(rc.get("mismatches").and_then(Json::as_u64), Some(0), "{}", m.name);
        assert!(rc.get("random_cases").and_then(Json::as_u64).unwrap_or(0) >= evidence::REQUIRED_RANDOM_CASES, "{}", m.name);
    }
}

/// Host runs of the feature-only variant sets (`evidence::SetRecord`,
/// optimizer headroom report): the committed record holds the `v3_scalar`
/// runs under Rosetta 2, which does not report LZCNT/BMI1/BMI2, so they are
/// diagnostics and no feature-only set has evidence (fail closed); passing
/// runs of every harness suite on a CPU that reports the features validate
/// the set, a failure anywhere withdraws it, a non-validating executor never
/// counts, and a set whose feature list changed has no evidence.
#[test]
fn feature_only_sets_need_a_host_run_on_a_cpu_that_reports_their_features() {
    let file = evidence::load(Arch::X86_64).unwrap();
    let diag: Vec<&evidence::SetRecord> = file.sets.iter().filter(|r| r.set == "v3_scalar").collect();
    assert!(diag.len() >= 4 && diag.iter().all(|r| r.status == "diagnostic" && r.executor == "rosetta2" && r.unreported == ["bmi1", "bmi2", "lzcnt"]), "{diag:?}");
    assert!(diag.iter().any(|r| r.suite == "qmdb-fixtures-n1" && r.cases == 32) && diag.iter().any(|r| r.suite == "qmdb-fixtures-n32" && r.cases == 490), "{diag:?}");
    assert!(matches!(evidence::set_verdict_in(&file, "v3_scalar", &v3()), evidence::SetVerdict::Missing(ref r) if r.contains("only diagnostic runs")));
    assert!(matches!(evidence::set_verdict_in(&file, "v4", &v3()), evidence::SetVerdict::Missing(_)));
    // full runs on a CPU that reports the features, edited in
    assert_eq!(set_verdict(full_runs(ZEN5, &[])), evidence::SetVerdict::Validated { cpus: vec![ZEN5.to_string()] });
    let mut failed = full_runs(ZEN5, &[]);
    failed.push(set_run(OTHER, &[("mismatches", Json::uint(3)), ("status", Json::str("failed"))]));
    assert!(matches!(set_verdict(failed), evidence::SetVerdict::Missing(ref r) if r.contains("disagreed")));
    assert!(matches!(set_verdict(full_runs(ZEN5, &[("executor", Json::str("sde"))])), evidence::SetVerdict::Missing(_)));
    // runs of the set as it was defined before (another feature list) are
    // not evidence for the set as defined now
    let old: Vec<Json> = ["popcnt", "lzcnt"].iter().map(|f| Json::str(*f)).collect();
    let old_hash = evidence::set_hash("v3_scalar", &["popcnt".to_string(), "lzcnt".to_string()]);
    assert!(matches!(set_verdict(full_runs(ZEN5, &[("features", Json::Arr(old)), ("set_hash", Json::str(old_hash))])), evidence::SetVerdict::Missing(_)));
    // the hash does not depend on the order of the features
    let mut rev = v3();
    rev.reverse();
    assert_eq!(evidence::set_hash("v3_scalar", &v3()), evidence::set_hash("v3_scalar", &rev));
    assert_eq!(evidence::set_run_status(10, 0, &["lzcnt".to_string()]), "diagnostic");
    assert_eq!(evidence::set_run_status(10, 1, &[]), "failed");
    assert_eq!(evidence::set_run_status(0, 0, &[]), "skipped");
}

const OTHER: &str = "GenuineIntel/06-8f-08/0x2b000590";

fn v3() -> Vec<String> {
    ["popcnt", "lzcnt", "bmi1", "bmi2"].iter().map(|s| s.to_string()).collect()
}

/// A passing `v3_scalar` run of `qmdb-fixtures-n32` on `cpu`, with `edits`
/// applied (a field set to `Json::Null` is removed).
fn set_run(cpu: &str, edits: &[(&str, Json)]) -> Json {
    let mut obj = Json::Obj(vec![
        ("cpu_key".into(), Json::str(cpu)),
        ("executor".into(), Json::str("native")),
        ("set".into(), Json::str("v3_scalar")),
        ("features".into(), Json::Arr(v3().into_iter().map(Json::str).collect())),
        ("set_hash".into(), Json::str(evidence::set_hash("v3_scalar", &v3()))),
        ("suite".into(), Json::str("qmdb-fixtures-n32")),
        ("cases".into(), Json::uint(490)),
        ("mismatches".into(), Json::uint(0)),
        ("status".into(), Json::str("passed")),
        ("unreported_features".into(), Json::Arr(vec![])),
    ]);
    for (k, v) in edits {
        if matches!(v, Json::Null) {
            if let Json::Obj(fields) = &mut obj {
                fields.retain(|(f, _)| f != k);
            }
        } else {
            set(&mut obj, k, v.clone());
        }
    }
    obj
}

/// Passing runs of every harness suite (`evidence::SET_SUITES`) on `cpu`,
/// each at the harness's default size, with `edits` applied to each.
fn full_runs(cpu: &str, edits: &[(&str, Json)]) -> Vec<Json> {
    [("qmdb-fixtures-n1", 32), ("qmdb-fixtures-n32", 490), ("shape-differential-n1", 1_000_289), ("shape-differential-n32", 1_000_289)]
        .iter()
        .map(|(suite, cases)| {
            let mut e: Vec<(&str, Json)> = vec![("suite", Json::str(*suite)), ("cases", Json::uint(*cases))];
            e.extend(edits.iter().cloned());
            set_run(cpu, &e)
        })
        .collect()
}

/// The committed x86_64 record with `extra` set runs appended, as text.
fn with_set_runs(extra: Vec<Json>) -> String {
    let text = std::fs::read_to_string(evidence::evidence_path(Arch::X86_64)).unwrap();
    let mut doc = json::parse(&text).unwrap();
    let mut sets: Vec<Json> = doc.get("sets").and_then(Json::as_array).unwrap_or(&[]).to_vec();
    sets.extend(extra);
    set(&mut doc, "sets", Json::Arr(sets));
    doc.to_pretty()
}

fn set_verdict(extra: Vec<Json>) -> evidence::SetVerdict {
    evidence::set_verdict_in(&evidence::parse(&with_set_runs(extra)).unwrap(), "v3_scalar", &v3())
}

/// Headroom fix review: a set run whose counts or feature lists have the
/// wrong type read as zero / empty and validated the set. A set run is now
/// read strictly, and a malformed one makes the file unusable (fail closed).
#[test]
fn malformed_set_runs_reject_the_file() {
    for (what, edit) in [
        ("mismatches as a string", ("mismatches", Json::str("7"))),
        ("mismatches in exponent form", ("mismatches", Json::Num("1e3".into()))),
        ("negative mismatches", ("mismatches", Json::Num("-1".into()))),
        ("cases as a string", ("cases", Json::str("490"))),
        ("missing cases", ("cases", Json::Null)),
        ("unreported features as a string", ("unreported_features", Json::str("lzcnt,bmi1,bmi2"))),
        ("unreported features with a number", ("unreported_features", Json::Arr(vec![Json::uint(1)]))),
        ("missing unreported features", ("unreported_features", Json::Null)),
        ("missing features", ("features", Json::Null)),
        ("unknown status", ("status", Json::str("FAILED"))),
        ("features that do not match the hash", ("features", Json::Arr(vec![Json::str("popcnt")]))),
        ("an unreported feature outside the set", ("unreported_features", Json::Arr(vec![Json::str("avx2")]))),
    ] {
        let mut runs = full_runs(ZEN5, &[]);
        runs.push(set_run(OTHER, &[edit]));
        assert!(evidence::parse(&with_set_runs(runs)).is_err(), "{what}: accepted");
    }
}

/// Headroom fix review: a run on another CPU whose status is not `failed`
/// but which records mismatches, or whose status disagrees with its counts,
/// did not withdraw a pass elsewhere. Any mismatch, and any status the
/// counts contradict, now withdraws the set.
#[test]
fn any_mismatch_or_inconsistent_status_withdraws_the_set() {
    for (what, edits) in [
        ("skipped with mismatches", vec![("status", Json::str("skipped")), ("mismatches", Json::uint(7))]),
        ("passed with mismatches", vec![("mismatches", Json::uint(7))]),
        ("diagnostic with mismatches", vec![("status", Json::str("diagnostic")), ("mismatches", Json::uint(7)), ("unreported_features", Json::Arr(vec![Json::str("lzcnt")]))]),
        ("skipped although it ran", vec![("status", Json::str("skipped"))]),
        ("passed with nothing run", vec![("cases", Json::uint(0))]),
        ("passed with an unreported feature", vec![("unreported_features", Json::Arr(vec![Json::str("lzcnt")]))]),
    ] {
        let mut runs = full_runs(ZEN5, &[]);
        runs.push(set_run(OTHER, &edits));
        assert!(matches!(set_verdict(runs), evidence::SetVerdict::Missing(_)), "{what}: still validated");
    }
}

/// Headroom fix review: one passing run of any suite with one case
/// validated the set, so a host-kit dry run (2·10^4 `shape` cases) could
/// enable dispatch. Every harness suite must now pass on the same CPU, and a
/// shape differential needs at least 10^6 cases.
#[test]
fn a_set_needs_every_harness_suite_at_full_size_on_one_cpu() {
    assert!(matches!(set_verdict(vec![set_run(ZEN5, &[("suite", Json::str("anything")), ("cases", Json::uint(1))])]), evidence::SetVerdict::Missing(ref r) if r.contains("incomplete")));
    let mut runs = full_runs(ZEN5, &[]);
    runs.retain(|r| r.get("suite").and_then(Json::as_str) != Some("shape-differential-n32"));
    assert!(matches!(set_verdict(runs), evidence::SetVerdict::Missing(ref r) if r.contains("shape-differential-n32")));
    // a dry run: full fixture suites, 20,000 random shape inputs
    let dry: Vec<Json> = full_runs(ZEN5, &[])
        .into_iter()
        .map(|mut r| {
            if r.get("suite").and_then(Json::as_str).is_some_and(|s| s.starts_with("shape")) {
                set(&mut r, "cases", Json::uint(20_289));
            }
            r
        })
        .collect();
    assert!(matches!(set_verdict(dry), evidence::SetVerdict::Missing(_)));
    // the suites split across two CPUs do not add up
    let mut split = full_runs(ZEN5, &[]);
    for r in split.iter_mut().skip(2) {
        set(r, "cpu_key", Json::str(OTHER));
    }
    assert!(matches!(set_verdict(split), evidence::SetVerdict::Missing(_)));
    assert_eq!(evidence::set_suite_min_cases("shape-differential-n1"), evidence::REQUIRED_SHAPE_CASES);
}

/// Headroom fix review: a record on the Rosetta 2 CPU key that claims every
/// feature is reported validated the set, although that CPU's other runs
/// say it does not report LZCNT/BMI1/BMI2. A CPU that any record says lacks
/// a feature of the set never counts for it; neither does one whose host
/// summary records the feature as not detected.
#[test]
fn a_cpu_that_other_records_say_lacks_a_feature_does_not_count() {
    let rosetta = "GenuineIntel/06-2c-00/unknown+rosetta2";
    assert!(evidence::load(Arch::X86_64).unwrap().sets.iter().any(|r| r.cpu_key == rosetta));
    let v = set_verdict(full_runs(rosetta, &[("executor", Json::str("native"))]));
    assert!(matches!(v, evidence::SetVerdict::Missing(ref r) if r.contains("does not report")), "{v:?}");
    // a host summary of the CPU that records a feature as not detected
    let text = with_set_runs(full_runs(ZEN5, &[]));
    let mut doc = json::parse(&text).unwrap();
    let mut hosts: Vec<Json> = doc.get("hosts").and_then(Json::as_array).unwrap().to_vec();
    for h in hosts.iter_mut().filter(|h| h.get("cpu_key").and_then(Json::as_str) == Some(ZEN5)) {
        let mut m = h.get("machine").unwrap().clone();
        let mut df = m.get("detected_features").unwrap().clone();
        set(&mut df, "bmi2", Json::Bool(false));
        set(&mut m, "detected_features", df);
        set(h, "machine", m);
    }
    set(&mut doc, "hosts", Json::Arr(hosts));
    let file = evidence::parse(&doc.to_pretty()).unwrap();
    assert!(matches!(evidence::set_verdict_in(&file, "v3_scalar", &v3()), evidence::SetVerdict::Missing(ref r) if r.contains("bmi2")));
}

/// Headroom fix review: `model_hash` memoized by the `Model`'s address, so
/// a temporary `Model` built at the same address as an earlier one got the
/// earlier one's hash. The memo is now keyed by the model's items.
#[test]
fn model_hash_of_a_temporary_model_is_its_own() {
    let variant = |i: usize| {
        let mut m = registry::X86_64[0].clone();
        m.items = registry::X86_64[i].items;
        m.name = registry::X86_64[i].name;
        evidence::model_hash(&m)
    };
    for i in 0..registry::X86_64.len().min(8) {
        assert_eq!(variant(i), evidence::model_hash(&registry::X86_64[i]), "model {i}");
    }
}
