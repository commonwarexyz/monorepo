//! The hardware side of the feature-only known-answer tests
//! (`sandblaster_targets::evidence::kat`): one `#[target_feature]` function
//! per KAT that executes the instruction, compared with the known answers
//! and, on random inputs, with the bit-loop reference.
//!
//! Every function is `#[inline(never)]` and `#[no_mangle]`
//! (`sandblaster_kat_<name>`) so the host kit can check on the disassembly
//! that it really contains the instruction under test
//! (`KatSpec::instructions`), not a folded or scalar-emulated form.
//!
//! A function is called only when the CPU reports its feature, except in
//! the `--kat-force` diagnostic, which runs the four F3-prefixed encodings
//! (`lzcnt`, `tzcnt`) regardless: on a CPU without LZCNT/BMI1 they execute
//! as `bsr`/`bsf` and return different values instead of faulting — the
//! hazard the run-time self-test of design §13.2 guards against. Forced
//! results are recorded as `diagnostic`, never as evidence.
// Off x86_64 only `run` (which returns nothing) is used.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code, unused_imports))]

use sandblaster_targets::diff::{self, Config, Outcome};
use sandblaster_targets::evidence::{KatOutcome, kat};

/// The KATs whose encodings decode as legacy instructions (no fault) on CPUs
/// without the feature, i.e. the only ones `--kat-force` may execute.
pub const FORCIBLE: [&str; 4] = ["lzcnt_u64", "lzcnt_u32", "tzcnt_u64", "tzcnt_u32"];

#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)]
mod x86 {
    use core::arch::x86_64::*;

    macro_rules! kat_fns {
        ($( $sym:ident, $feat:literal, |$a:ident, $b:ident| $body:expr; )*) => {
            $(
                #[inline(never)]
                #[unsafe(no_mangle)]
                #[target_feature(enable = $feat)]
                pub fn $sym($a: u64, $b: u64) -> u64 {
                    let _ = $b;
                    // SAFETY: the intrinsics below take no pointers; the
                    // function's own target feature covers them.
                    unsafe { $body }
                }
            )*
        };
    }

    kat_fns! {
        sandblaster_kat_lzcnt_u64, "lzcnt", |a, b| _lzcnt_u64(a);
        sandblaster_kat_lzcnt_u32, "lzcnt", |a, b| u64::from(_lzcnt_u32(a as u32));
        sandblaster_kat_tzcnt_u64, "bmi1", |a, b| _tzcnt_u64(a);
        sandblaster_kat_tzcnt_u32, "bmi1", |a, b| u64::from(_tzcnt_u32(a as u32));
        sandblaster_kat_andn_u64, "bmi1", |a, b| _andn_u64(a, b);
        sandblaster_kat_bextr_u64, "bmi1", |a, b| _bextr2_u64(a, b);
        sandblaster_kat_blsi_u64, "bmi1", |a, b| _blsi_u64(a);
        sandblaster_kat_blsmsk_u64, "bmi1", |a, b| _blsmsk_u64(a);
        sandblaster_kat_blsr_u64, "bmi1", |a, b| _blsr_u64(a);
        sandblaster_kat_bzhi_u64, "bmi2", |a, b| _bzhi_u64(a, b as u32);
        sandblaster_kat_pdep_u64, "bmi2", |a, b| _pdep_u64(a, b);
        sandblaster_kat_pext_u64, "bmi2", |a, b| _pext_u64(a, b);
        sandblaster_kat_mulx_hi_u64, "bmi2", |a, b| { let mut hi = 0u64; let _lo = _mulx_u64(a, b, &mut hi); hi };
        sandblaster_kat_mulx_lo_u64, "bmi2", |a, b| { let mut hi = 0u64; let lo = _mulx_u64(a, b, &mut hi); core::hint::black_box(hi); lo };
        sandblaster_kat_shlx_u64, "bmi2", |a, b| a << (b & 63);
        sandblaster_kat_shrx_u64, "bmi2", |a, b| a >> (b & 63);
        sandblaster_kat_sarx_u64, "bmi2", |a, b| ((a as i64) >> (b & 63)) as u64;
        sandblaster_kat_rorx13_u64, "bmi2", |a, b| a.rotate_right(13);
        sandblaster_kat_popcnt_u64, "popcnt", |a, b| _popcnt64(a as i64) as u64;
        sandblaster_kat_popcnt_u32, "popcnt", |a, b| _popcnt32(a as u32 as i32) as u64;
    }

    /// The hardware function of KAT `name`.
    pub fn hw(name: &str) -> Option<unsafe fn(u64, u64) -> u64> {
        Some(match name {
            "lzcnt_u64" => sandblaster_kat_lzcnt_u64,
            "lzcnt_u32" => sandblaster_kat_lzcnt_u32,
            "tzcnt_u64" => sandblaster_kat_tzcnt_u64,
            "tzcnt_u32" => sandblaster_kat_tzcnt_u32,
            "andn_u64" => sandblaster_kat_andn_u64,
            "bextr_u64" => sandblaster_kat_bextr_u64,
            "blsi_u64" => sandblaster_kat_blsi_u64,
            "blsmsk_u64" => sandblaster_kat_blsmsk_u64,
            "blsr_u64" => sandblaster_kat_blsr_u64,
            "bzhi_u64" => sandblaster_kat_bzhi_u64,
            "pdep_u64" => sandblaster_kat_pdep_u64,
            "pext_u64" => sandblaster_kat_pext_u64,
            "mulx_hi_u64" => sandblaster_kat_mulx_hi_u64,
            "mulx_lo_u64" => sandblaster_kat_mulx_lo_u64,
            "shlx_u64" => sandblaster_kat_shlx_u64,
            "shrx_u64" => sandblaster_kat_shrx_u64,
            "sarx_u64" => sandblaster_kat_sarx_u64,
            "rorx13_u64" => sandblaster_kat_rorx13_u64,
            "popcnt_u64" => sandblaster_kat_popcnt_u64,
            "popcnt_u32" => sandblaster_kat_popcnt_u32,
            _ => return None,
        })
    }

    pub fn detected(feature: &str) -> bool {
        match feature {
            "lzcnt" => std::arch::is_x86_feature_detected!("lzcnt"),
            "bmi1" => std::arch::is_x86_feature_detected!("bmi1"),
            "bmi2" => std::arch::is_x86_feature_detected!("bmi2"),
            "popcnt" => std::arch::is_x86_feature_detected!("popcnt"),
            _ => false,
        }
    }
}

/// Run-time detection of the features the design's x86 variant sets use
/// (design §13.1, §13.4), recorded in the evidence machine record next to
/// the detection of `sandblaster_targets::hw` (which stops at `avx512f`).
pub fn extra_features() -> Vec<(String, bool)> {
    #[cfg(target_arch = "x86_64")]
    {
        macro_rules! det {
            ($($f:tt),*) => { vec![$( ($f.to_string(), std::arch::is_x86_feature_detected!($f)) ),*] };
        }
        // (plus every other feature of the optimizer's feature-only sets,
        // e.g. `v4`'s implied `sse`, `sse3`, `f16c`: a set run counts only
        // on a CPU that reports all of them, `evidence::set_run_json`)
        det!["popcnt", "lzcnt", "bmi1", "bmi2", "fma", "avx512bw", "avx512vl", "avx512dq", "avx512cd", "avx512ifma", "avx512vbmi", "avx512vbmi2", "avx512vpopcntdq", "avx512bitalg", "gfni", "vaes", "vpclmulqdq", "sse", "sse3", "f16c"]
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Vec::new()
    }
}

/// The detected features of `sandblaster_targets::hw` plus [`extra_features`].
pub fn all_features(mut base: Vec<(String, bool)>) -> Vec<(String, bool)> {
    for (f, b) in extra_features() {
        if !base.iter().any(|(g, _)| *g == f) {
            base.push((f, b));
        }
    }
    base
}

/// Shape the second operand so the interesting range is covered: small bit
/// indices for `bzhi`, small start/length fields for `bextr` (the random
/// phase otherwise almost never hits indices below 64).
fn shape_b(name: &str, b: u64) -> u64 {
    match name {
        "bzhi_u64" => (b >> 8) & 0xff00 | (b % 72),
        "bextr_u64" => (b % 72) | (((b >> 16) % 72) << 8),
        _ => b,
    }
}

/// Run every KAT (x86_64 only; an empty list elsewhere). `force` adds the
/// diagnostic run of [`FORCIBLE`] on CPUs that do not report the feature.
pub fn run(cfg: &Config, force: bool) -> Vec<KatOutcome> {
    #[cfg(target_arch = "x86_64")]
    {
        kat::KATS.iter().map(|k| run_one(k, cfg, force)).collect()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (cfg, force);
        Vec::new()
    }
}

#[cfg(target_arch = "x86_64")]
fn run_one(k: &kat::KatSpec, cfg: &Config, force: bool) -> KatOutcome {
    use std::hint::black_box as bb;
    let detected = x86::detected(k.feature);
    let forced = !detected && force && FORCIBLE.contains(&k.name);
    let skipped = |reason: String| KatOutcome {
        name: k.name.into(),
        feature: k.feature.into(),
        known_answers: 0,
        known_failures: 0,
        differential: Outcome::skipped(k.name, reason),
        forced: false,
    };
    if !detected && !forced {
        return skipped(format!("CPU lacks `{}`", k.feature));
    }
    let f = x86::hw(k.name).expect("every KAT has a hardware function");
    let mut known_failures = 0;
    let mut first: Option<String> = None;
    for &(a, b, e) in k.known {
        // SAFETY: the feature was detected (or this is the forced diagnostic
        // of an encoding that cannot fault, see FORCIBLE).
        let got = bb(unsafe { f(bb(a), bb(b)) });
        if got != e {
            known_failures += 1;
            first.get_or_insert_with(|| format!("{}({a:#x}, {b:#x}) = {got:#x}, expected {e:#x}", k.name));
        }
    }
    let name = k.name;
    let mut differential = diff::diff2(
        name,
        cfg.random_per_model,
        cfg.seed_for(name),
        |a: i64, b: i64| (k.reference)(a as u64, shape_b(name, b as u64)),
        // SAFETY: as above.
        |a: i64, b: i64| unsafe { f(a as u64, shape_b(name, b as u64)) },
    );
    if differential.first_mismatch.is_none() {
        differential.first_mismatch = first;
    } else if let Some(fk) = first {
        differential.first_mismatch = Some(format!("{fk}; {}", differential.first_mismatch.take().unwrap_or_default()));
    }
    KatOutcome { name: k.name.into(), feature: k.feature.into(), known_answers: k.known.len() as u64, known_failures, differential, forced }
}

/// One line per KAT.
pub fn summary(o: &KatOutcome) -> String {
    match &o.differential.skipped {
        Some(r) => format!("KAT {:<14} SKIPPED: {r}", o.name),
        None => format!(
            "KAT {:<14} {}{}: {} known answers ({} wrong) + {} random + {} corner cases, {} mismatches{}",
            o.name,
            o.status(),
            if o.forced { " (forced: CPU does not report the feature)" } else { "" },
            o.known_answers,
            o.known_failures,
            o.differential.random,
            o.differential.corner,
            o.differential.mismatches,
            o.differential.first_mismatch.as_deref().map(|m| format!("; first: {m}")).unwrap_or_default()
        ),
    }
}
