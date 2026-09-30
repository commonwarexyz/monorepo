//! Tuning evidence: measured cost-model constants of one microarchitecture
//! (design §19.3, `evidence/tuning-<arch>-<uarch>.json`).
//!
//! Tuning evidence **changes choices only** (design §19 "Gating"): it feeds
//! the cost model (break-even widths, interleave factors, thread
//! thresholds), never dispatch, and a wrong constant costs speed, never
//! correctness. It is therefore validated for shape, not for provenance:
//! [`check`] verifies the schema, that every key the cost model reads
//! ([`required_keys`]) is present either as a measured value or with a
//! recorded reason in `skipped`, and that every value is a finite
//! non-negative number with a unit and a source.
//!
//! The format (schema `sandblaster-tuning-evidence/1`) is a flat map from
//! dotted keys to `{"value": <number>, "unit": "...", "source": "..."}` so
//! the optimizer (O8, which will own the consuming side) can look constants
//! up by name. The host kit (`tools/host-kit`) writes it; the evidence
//! binary validates it (`--check-tuning`).
#![forbid(unsafe_code)]

use crate::json::Json;
use crate::registry::Arch;

/// Schema identifier of the tuning evidence.
pub const SCHEMA: &str = "sandblaster-tuning-evidence/1";

/// The committed tuning evidence (`evidence/tuning-<arch>-<uarch>.json`),
/// embedded so the optimizer's cost model (plan O8, `opt::cost::tuning`)
/// reads exactly these bytes: `(file name, text)`, sorted by name. Their
/// hash is part of the optimizer's determinism key; changing a file changes
/// choices only (never what is admitted or dispatched).
pub const COMMITTED: &[(&str, &str)] = &[
    ("tuning-aarch64-m5.json", include_str!("../../evidence/tuning-aarch64-m5.json")),
    ("tuning-x86_64-zen5.json", include_str!("../../evidence/tuning-x86_64-zen5.json")),
];

/// Scalar operations whose latency and throughput are recorded on x86_64.
pub const X86_OPS: &[&str] = &[
    "add_r64", "imul_r64", "lzcnt_r64", "tzcnt_r64", "popcnt_r64", "pext_r64", "pdep_r64", "bzhi_r64", "shlx_r64", "mulx_r64",
    "crc32_r64", "paddd_xmm", "pshufb_xmm", "sha256rnds2", "sha256msg1", "sha256msg2", "aesenc_xmm", "pclmulqdq_xmm",
    "vpaddd_ymm", "vpaddd_zmm", "vpternlogd_ymm", "vpternlogd_zmm", "vprord_zmm", "vpshufb_zmm", "vpermd_zmm",
    "vpmadd52luq_ymm", "vpmadd52luq_zmm", "vgf2p8affineqb_zmm", "vpopcntq_zmm", "vpclmulqdq_zmm", "vaesenc_zmm",
];

/// Operations recorded on aarch64.
pub const AARCH64_OPS: &[&str] = &[
    "add_x", "mul_x", "clz_x", "rbit_x", "cnt_v8b", "eor_v16b", "tbl_v16b", "add_v4s", "sha256h", "sha256su0", "sha256su1",
    "eor3_v16b", "pmull_v1q", "aese_v16b",
];

/// The keys the cost model reads for `arch` (all must be measured or
/// skipped with a reason).
pub fn required_keys(arch: Arch) -> Vec<String> {
    let mut keys: Vec<String> = vec!["cycle_ns".into()];
    let ops = match arch {
        Arch::X86_64 => X86_OPS,
        Arch::Aarch64 => AARCH64_OPS,
    };
    for op in ops {
        keys.push(format!("op.{op}.latency_cycles"));
        keys.push(format!("op.{op}.throughput_cycles"));
    }
    keys.extend(
        [
            // SHA-256 kernels (par): single-stream latency, interleaved throughput, saturation.
            "sha.hw.latency_ns_per_msg",
            "sha.hw.x1.ns_per_msg",
            "sha.hw.x2.ns_per_msg",
            "sha.hw.x3.ns_per_msg",
            "sha.hw.x4.ns_per_msg",
            "sha.hw.k_sat",
            "sha.portable.ns_per_msg",
            // threads (par calib): fork-join overheads and break-even work
            "threads.logical_cpus",
            "threads.t",
            "threads.o_fork_ns",
            "threads.theta_enter_ns.parked",
            "threads.theta_enter_ns.warm",
            "threads.theta_enter_ns.spinning",
            "threads.break_even_ns.warm",
            "threads.break_even_ns.parked",
            "threads.os_spawn_join_ns",
            // crossovers
            "crossover.merkle_level_pairs",
            "crossover.tree_subtree_speedup_2p16",
            // memory
            "memory.read_gib_s",
            "memory.copy_gib_s",
            // varint decoding (corpus qmdb rows)
            "varint.loop_ns.1B",
            "varint.loop_ns.9B",
            "varint.unrolled_ns.1B",
            "varint.unrolled_ns.2B",
            "varint.unrolled_ns.5B",
            "varint.unrolled_ns.9B",
            "varint.swar_ns.1B",
            "varint.swar_ns.2B",
            "varint.swar_ns.5B",
            "varint.swar_ns.9B",
        ]
        .map(String::from),
    );
    if arch == Arch::X86_64 {
        keys.extend(
            [
                // AVX-512 x16 / EVEX-256 x8 software SHA-256 and the lane break-even b*
                "sha.x16.ns_per_msg",
                "sha.x8_256.ns_per_msg",
                "sha.x16.b_star",
                "sha.x8_256.b_star",
                // 512- vs 256-bit: per-message time of the 256-bit kernel / the 512-bit kernel
                "simd.ratio_512_over_256",
                "simd.prefer_512",
                "varint.pext_crossover_bytes",
            ]
            .map(String::from),
        );
    }
    keys
}

/// A validated tuning file's summary.
#[derive(Clone, Debug, PartialEq)]
pub struct TuningSummary {
    /// Architecture.
    pub arch: Arch,
    /// Microarchitecture name.
    pub uarch: String,
    /// CPU key of the machine (see [`super::cpu::CpuId::key_on`]).
    pub cpu_key: String,
    /// Whether the kit ran in dry-run mode (tiny sample counts: not for use).
    pub dry_run: bool,
    /// Keys with a measured value.
    pub measured: usize,
    /// Keys skipped with a reason.
    pub skipped: usize,
}

fn num(j: &Json) -> Option<f64> {
    match j {
        Json::Num(s) => s.parse().ok(),
        _ => None,
    }
}

/// Validate a tuning evidence document; `Err` lists every problem.
pub fn check(text: &str) -> Result<TuningSummary, Vec<String>> {
    let doc = crate::json::parse(text).map_err(|e| vec![e.to_string()])?;
    let mut errs = Vec::new();
    let s = |k: &str| doc.get(k).and_then(Json::as_str).map(str::to_string);
    if s("schema").as_deref() != Some(SCHEMA) {
        errs.push(format!("schema must be `{SCHEMA}`"));
    }
    let arch = s("arch").and_then(|a| Arch::from_name(&a));
    if arch.is_none() {
        errs.push("missing or unknown `arch`".into());
    }
    for k in ["uarch", "cpu_key", "date", "rustc", "executor"] {
        if s(k).is_none_or(|v| v.is_empty()) {
            errs.push(format!("missing string `{k}`"));
        }
    }
    let dry_run = doc.get("kit").and_then(|k| k.get("dry_run")).and_then(Json::as_bool);
    if dry_run.is_none() {
        errs.push("missing boolean `kit.dry_run`".into());
    }
    let empty = Vec::new();
    let values = match doc.get("values") {
        Some(Json::Obj(m)) => m,
        _ => {
            errs.push("missing object `values`".into());
            &empty
        }
    };
    let skipped = match doc.get("skipped") {
        Some(Json::Obj(m)) => m,
        _ => {
            errs.push("missing object `skipped`".into());
            &empty
        }
    };
    for (k, v) in values {
        match v.get("value").and_then(num) {
            Some(x) if x.is_finite() && x >= 0.0 => {}
            _ => errs.push(format!("values.{k}: `value` must be a finite non-negative number")),
        }
        for f in ["unit", "source"] {
            if v.get(f).and_then(Json::as_str).is_none_or(str::is_empty) {
                errs.push(format!("values.{k}: missing `{f}`"));
            }
        }
        if skipped.iter().any(|(s, _)| s == k) {
            errs.push(format!("{k} is both measured and skipped"));
        }
    }
    for (k, v) in skipped {
        if v.as_str().is_none_or(str::is_empty) {
            errs.push(format!("skipped.{k}: the reason must be a non-empty string"));
        }
    }
    if let Some(arch) = arch {
        for k in required_keys(arch) {
            if !values.iter().any(|(v, _)| *v == k) && !skipped.iter().any(|(s, _)| *s == k) {
                errs.push(format!("required key `{k}` is neither measured nor skipped"));
            }
        }
    }
    if !errs.is_empty() {
        return Err(errs);
    }
    Ok(TuningSummary {
        arch: arch.expect("checked"),
        uarch: s("uarch").unwrap_or_default(),
        cpu_key: s("cpu_key").unwrap_or_default(),
        dry_run: dry_run.unwrap_or(true),
        measured: values.len(),
        skipped: skipped.len(),
    })
}

/// The value of `key` in a tuning document, if measured.
pub fn value(doc: &Json, key: &str) -> Option<f64> {
    doc.get("values")?.get(key)?.get("value").and_then(num)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(arch: Arch, drop: Option<&str>, bad: Option<&str>) -> String {
        let mut values = Vec::new();
        let mut skipped = Vec::new();
        for (i, k) in required_keys(arch).into_iter().enumerate() {
            if Some(k.as_str()) == drop {
                continue;
            }
            if i % 5 == 0 {
                skipped.push((k, Json::str("CPU lacks the feature")));
            } else {
                let v = if Some(k.as_str()) == bad { Json::Num("-1".into()) } else { Json::Num("1.5".into()) };
                values.push((k, Json::obj([("value", v), ("unit", Json::str("ns")), ("source", Json::str("test"))])));
            }
        }
        Json::obj([
            ("schema", Json::str(SCHEMA)),
            ("arch", Json::str(arch.name())),
            ("uarch", Json::str("zen5")),
            ("cpu_key", Json::str("AuthenticAMD/1a-02-01/0xb002110")),
            ("executor", Json::str("native")),
            ("date", Json::str("2026-10-01")),
            ("rustc", Json::str("rustc test")),
            ("kit", Json::obj([("version", Json::str("hostkit/1")), ("dry_run", Json::Bool(false))])),
            ("values", Json::Obj(values)),
            ("skipped", Json::Obj(skipped)),
        ])
        .to_pretty()
    }

    #[test]
    fn complete_documents_pass() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let s = check(&doc(arch, None, None)).unwrap_or_else(|e| panic!("{e:?}"));
            assert_eq!(s.arch, arch);
            assert!(!s.dry_run);
            assert_eq!(s.measured + s.skipped, required_keys(arch).len());
        }
        assert!(required_keys(Arch::X86_64).contains(&"sha.x16.b_star".to_string()));
        assert!(!required_keys(Arch::Aarch64).contains(&"sha.x16.b_star".to_string()));
    }

    #[test]
    fn committed_files_are_valid() {
        let mut names: Vec<&str> = COMMITTED.iter().map(|(n, _)| *n).collect();
        let sorted = { let mut v = names.clone(); v.sort(); v };
        assert_eq!(names, sorted, "COMMITTED must be sorted by name");
        for (name, text) in COMMITTED {
            let s = check(text).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert!(!s.dry_run, "{name} is a dry run");
            assert_eq!(*name, format!("tuning-{}-{}.json", s.arch.name(), s.uarch), "{name}: file name must match arch and uarch");
        }
        // every committed file is listed
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence");
        for e in std::fs::read_dir(dir).unwrap() {
            let n = e.unwrap().file_name().into_string().unwrap();
            if n.starts_with("tuning-") {
                assert!(names.contains(&n.as_str()), "{n} is not in COMMITTED");
            }
        }
        names.clear();
    }

    #[test]
    fn missing_or_bad_keys_fail() {
        let e = check(&doc(Arch::X86_64, Some("threads.o_fork_ns"), None)).unwrap_err();
        assert!(e.iter().any(|m| m.contains("threads.o_fork_ns")), "{e:?}");
        let e = check(&doc(Arch::X86_64, None, Some("memory.read_gib_s"))).unwrap_err();
        assert!(e.iter().any(|m| m.contains("memory.read_gib_s")), "{e:?}");
        assert!(check("{}").is_err());
        assert!(check("not json").is_err());
        let d = crate::json::parse(&doc(Arch::X86_64, None, None)).unwrap();
        let keys = required_keys(Arch::X86_64);
        assert_eq!(value(&d, &keys[1]), Some(1.5));
        assert_eq!(value(&d, &keys[0]), None); // skipped
    }
}
