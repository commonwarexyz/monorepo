//! Target description and the target-feature implication closure
//! (DESIGN.md §2 "Target information", §9.3).
//!
//! * [`TargetInfo`] is built from `CARGO_CFG_TARGET_ARCH`,
//!   `CARGO_CFG_TARGET_FEATURE`, `CARGO_CFG_TARGET_ENDIAN`,
//!   `CARGO_CFG_TARGET_POINTER_WIDTH` in `build.rs` (never from the host), or
//!   from a named target in the CLI. It is used to evaluate target `cfg`
//!   predicates on items (items whose `cfg` is false are dropped, exactly as
//!   rustc does) and to check that `core::arch::<arch>` exists.
//! * [`feature_closure`] computes the implication closure of a function's
//!   **own** `#[target_feature]` list with rustc's implied-feature table
//!   (`sha2 → neon`, `sha3 → sha2`, `aes → neon`, `sha → sse2`,
//!   `avx2 → avx → sse4.2 → sse4.1 → ssse3 → sse3 → sse2 → sse`, ...).
//!   Static target features do **not** count (§9.3).
//!
//! Hardware code is first-class: intrinsics, vector types and
//! `#[target_feature]` elaborate onto the target models
//! (`sandblaster/targets`, DESIGN.md §9.2). Two native-dialect authoring
//! forms were removed with the optimizer and are refused:
//! `#[implements]` ([`NO_VARIANTS`]) and the `sandblaster::arch` load/store
//! helpers ([`NO_ARCH_HELPERS`]).

use std::collections::BTreeSet;

/// Why `#[implements]` is refused.
pub const NO_VARIANTS: &str = "hardware variants and their dispatch were removed with the optimizer: give the `#[target_feature]` function its own contract, or relate it to the portable function by a law";

/// Why `sandblaster::arch` is refused.
pub const NO_ARCH_HELPERS: &str = "the `sandblaster::arch` load/store helpers were native-dialect authoring glue, removed with the optimizer: take and return vector values, or build them with the modeled intrinsics";

/// Target architectures the target library knows.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Arch {
    Aarch64,
    X86_64,
    Other(String),
}

impl Arch {
    pub fn parse(s: &str) -> Arch {
        match s {
            "aarch64" => Arch::Aarch64,
            "x86_64" => Arch::X86_64,
            other => Arch::Other(other.to_string()),
        }
    }
    pub fn name(&self) -> &str {
        match self {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
            Arch::Other(s) => s,
        }
    }
}

/// The compilation target.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TargetInfo {
    pub arch: Arch,
    /// Statically enabled target features (only used for `cfg(target_feature)`
    /// evaluation and dispatch; never for the §9.3 feature rule).
    pub features: BTreeSet<String>,
    pub little_endian: bool,
    pub pointer_width: u32,
}

impl TargetInfo {
    /// `aarch64-apple-darwin` (static `neon, aes, sha2, sha3, ...`).
    pub fn aarch64_apple_darwin() -> TargetInfo {
        TargetInfo {
            arch: Arch::Aarch64,
            features: ["aes", "crc", "dit", "dotprod", "dpb", "dpb2", "fcma", "fhm", "flagm", "fp16", "frintts", "jsconv", "lor", "lse", "neon", "paca", "pacg", "pan", "pmuv3", "ras", "rcpc", "rcpc2", "rdm", "sb", "sha2", "sha3", "ssbs", "vh"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            little_endian: true,
            pointer_width: 64,
        }
    }

    /// `x86_64-apple-darwin` (static baseline `sse..ssse3, sse4.1, cmpxchg16b, fxsr`).
    pub fn x86_64_apple_darwin() -> TargetInfo {
        TargetInfo {
            arch: Arch::X86_64,
            features: ["cmpxchg16b", "fxsr", "sse", "sse2", "sse3", "sse4.1", "ssse3"].iter().map(|s| s.to_string()).collect(),
            little_endian: true,
            pointer_width: 64,
        }
    }

    /// The target this binary was compiled for (CLI default).
    pub fn host() -> TargetInfo {
        if cfg!(target_arch = "x86_64") {
            TargetInfo::x86_64_apple_darwin()
        } else if cfg!(target_arch = "aarch64") {
            TargetInfo::aarch64_apple_darwin()
        } else {
            TargetInfo { arch: Arch::Other(std::env::consts::ARCH.to_string()), features: BTreeSet::new(), little_endian: cfg!(target_endian = "little"), pointer_width: usize::BITS }
        }
    }

    /// Parses a target name (`aarch64`, `x86_64`, or a full triple starting
    /// with one of them).
    pub fn from_name(name: &str) -> Option<TargetInfo> {
        if name.starts_with("aarch64") {
            Some(TargetInfo::aarch64_apple_darwin())
        } else if name.starts_with("x86_64") {
            Some(TargetInfo::x86_64_apple_darwin())
        } else {
            None
        }
    }

    /// Reads the `CARGO_CFG_*` variables of a build script via `get`.
    /// Returns an error message naming a missing variable.
    pub fn from_cargo_env(get: &dyn Fn(&str) -> Option<String>) -> Result<TargetInfo, String> {
        let arch = get("CARGO_CFG_TARGET_ARCH").ok_or("CARGO_CFG_TARGET_ARCH is not set")?;
        let features = get("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
        let endian = get("CARGO_CFG_TARGET_ENDIAN").ok_or("CARGO_CFG_TARGET_ENDIAN is not set")?;
        let width = get("CARGO_CFG_TARGET_POINTER_WIDTH").ok_or("CARGO_CFG_TARGET_POINTER_WIDTH is not set")?;
        Ok(TargetInfo {
            arch: Arch::parse(&arch),
            features: features.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            little_endian: endian == "little",
            pointer_width: width.parse().map_err(|_| format!("bad CARGO_CFG_TARGET_POINTER_WIDTH `{width}`"))?,
        })
    }
}

/// Features directly implied by `feature` on `arch` (rustc's table, the parts
/// relevant to the target library).
pub fn implied(arch: &Arch, feature: &str) -> &'static [&'static str] {
    match arch {
        Arch::Aarch64 => match feature {
            "aes" | "sha2" | "sm4" | "fp16" | "dotprod" | "rdm" | "i8mm" | "bf16" | "fcma" | "jsconv" | "frintts" => &["neon"],
            "sha3" => &["sha2"],
            "fhm" => &["fp16"],
            "sve" => &["neon", "fp16"],
            _ => &[],
        },
        Arch::X86_64 => match feature {
            "sse2" => &["sse"],
            "sse3" => &["sse2"],
            "ssse3" => &["sse3"],
            "sse4.1" => &["ssse3"],
            "sse4.2" => &["sse4.1"],
            "avx" => &["sse4.2"],
            "avx2" => &["avx"],
            "fma" | "f16c" => &["avx"],
            "avx512f" => &["avx2", "fma", "f16c"],
            "avx512bw" | "avx512cd" | "avx512dq" | "avx512vl" | "avx512ifma" | "avx512vpopcntdq" | "avx512vnni" => &["avx512f"],
            "avx512vbmi" | "avx512vbmi2" | "avx512bitalg" => &["avx512bw"],
            "sha" | "aes" | "pclmulqdq" | "gfni" => &["sse2"],
            "vaes" => &["avx2", "aes"],
            "vpclmulqdq" => &["avx", "pclmulqdq"],
            _ => &[],
        },
        Arch::Other(_) => &[],
    }
}

/// Whether `feature` is a known target feature of `arch` (unknown features are
/// rejected, like rustc does).
pub fn is_known_feature(arch: &Arch, feature: &str) -> bool {
    let known: &[&str] = match arch {
        Arch::Aarch64 => &["neon", "aes", "sha2", "sha3", "sm4", "fp16", "fhm", "dotprod", "rdm", "i8mm", "bf16", "crc", "lse", "rcpc", "rcpc2", "fcma", "jsconv", "frintts", "sve", "dit", "flagm", "ssbs", "sb", "paca", "pacg", "dpb", "dpb2", "lor", "pan", "ras", "vh", "pmuv3"],
        Arch::X86_64 => &["sse", "sse2", "sse3", "ssse3", "sse4.1", "sse4.2", "avx", "avx2", "fma", "f16c", "avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl", "avx512ifma", "avx512vpopcntdq", "avx512vnni", "avx512vbmi", "avx512vbmi2", "avx512bitalg", "sha", "aes", "pclmulqdq", "gfni", "vaes", "vpclmulqdq", "popcnt", "bmi1", "bmi2", "lzcnt", "adx", "movbe", "cmpxchg16b", "fxsr", "xsave"],
        Arch::Other(_) => &[],
    };
    known.contains(&feature)
}

/// Implication closure of a list of features (sorted, deduplicated).
pub fn feature_closure(arch: &Arch, features: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut work: Vec<String> = features.to_vec();
    while let Some(f) = work.pop() {
        if set.insert(f.clone()) {
            for g in implied(arch, &f) {
                work.push(g.to_string());
            }
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closure_follows_rustc_implications() {
        let s = feature_closure(&Arch::Aarch64, &["sha3".into()]);
        assert_eq!(s, vec!["neon", "sha2", "sha3"]);
        let s = feature_closure(&Arch::X86_64, &["sha".into(), "sse4.1".into()]);
        assert_eq!(s, vec!["sha", "sse", "sse2", "sse3", "sse4.1", "ssse3"]);
        let s = feature_closure(&Arch::X86_64, &["avx2".into()]);
        assert!(s.contains(&"sse4.2".to_string()) && s.contains(&"avx".to_string()));
    }
}
