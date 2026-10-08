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
    /// The build's `-C target-cpu` (`None`: the target's default) and
    /// `-C target-feature` flags (`CARGO_ENCODED_RUSTFLAGS`), when known: the
    /// reading of existing `unsafe` counts the static features only of a
    /// build at the target's defaults (DESIGN-UNSAFE-SIMD amendment A-S3).
    pub codegen_flags: Option<(Option<String>, String)>,
    /// The build's cfg set as far as a build script knows it
    /// ([`build_cfg`]), when known: `mir::load` binds an extraction's
    /// `(cfg ..)` record to it.
    pub cfg: Option<BuildCfg>,
}

/// A build's cfg set ([`build_cfg`]), or why its build script cannot know
/// it (its rustflags change it where no variable shows the result).
pub type BuildCfg = Result<BTreeSet<(String, Option<String>)>, String>;

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
            codegen_flags: None,
            cfg: None,
        }
    }

    /// `x86_64-apple-darwin` (static baseline `sse..ssse3, sse4.1, cmpxchg16b, fxsr`).
    pub fn x86_64_apple_darwin() -> TargetInfo {
        TargetInfo {
            arch: Arch::X86_64,
            features: ["cmpxchg16b", "fxsr", "sse", "sse2", "sse3", "sse4.1", "ssse3"].iter().map(|s| s.to_string()).collect(),
            little_endian: true,
            pointer_width: 64,
            codegen_flags: None,
            cfg: None,
        }
    }

    /// The target this binary was compiled for (CLI default).
    pub fn host() -> TargetInfo {
        if cfg!(target_arch = "x86_64") {
            TargetInfo::x86_64_apple_darwin()
        } else if cfg!(target_arch = "aarch64") {
            TargetInfo::aarch64_apple_darwin()
        } else {
            TargetInfo { arch: Arch::Other(std::env::consts::ARCH.to_string()), features: BTreeSet::new(), little_endian: cfg!(target_endian = "little"), pointer_width: usize::BITS, codegen_flags: None, cfg: None }
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
            codegen_flags: Some(codegen_flags(&get("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default())),
            cfg: Some(build_cfg(get)),
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

/// The codegen (`C`), unstable (`Z`) and optimization (`O`) options and
/// the `--cfg`s (`c`: the option has no short name) of a build's encoded
/// rustflags (`CARGO_ENCODED_RUSTFLAGS`, separated by `\x1f`), in order,
/// read as rustc's option parser (getopts) reads them: a long option's
/// value is its `=v`, else the next argument but for the flags `--help`,
/// `--test`, `--version` and `--verbose` (`--codegen v`, `--codegen=v`,
/// `--cfg v` and `--cfg=v` kept, every other long option's value
/// skipped); a group of short options — `-Cv`, `-C v`, `-O`, `-gO`,
/// `-gCv` —, any of the flags `g h O V v`, then at most one option that
/// takes a value, the group's rest or else the next argument (`C`, `Z`,
/// and `A D F L W l o`, whose values are skipped). So a `--cfg` that is
/// another option's value (`-L --cfg=x`) is no `--cfg`. An empty argument
/// is an argument (Cargo passes an empty segment on: `-A '' -O` sets
/// `-O`).
fn rustc_options(encoded: &str) -> Vec<(char, String)> {
    let args: Vec<&str> = encoded.split('\x1f').collect();
    let mut opts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        i += 1;
        if let Some(long) = a.strip_prefix("--") {
            let (name, v) = match long.split_once('=') {
                Some((name, v)) => (name, v),
                None if matches!(long, "help" | "test" | "version" | "verbose") => (long, ""),
                None => {
                    i += 1;
                    (long, args.get(i - 1).copied().unwrap_or(""))
                }
            };
            match name {
                "codegen" => opts.push(('C', v.to_string())),
                "cfg" => opts.push(('c', v.to_string())),
                _ => {}
            }
        } else if let Some(group) = a.strip_prefix('-') {
            for (j, c) in group.char_indices() {
                match c {
                    'g' | 'h' | 'V' | 'v' => {}
                    'O' => opts.push(('O', String::new())),
                    'C' | 'Z' | 'A' | 'D' | 'F' | 'L' | 'W' | 'l' | 'o' => {
                        let v = if j + 1 < group.len() {
                            &group[j + 1..]
                        } else {
                            i += 1;
                            args.get(i - 1).copied().unwrap_or("")
                        };
                        if c == 'C' || c == 'Z' {
                            opts.push((c, v.to_string()));
                        }
                        break;
                    }
                    _ => break,
                }
            }
        }
    }
    opts
}

/// The codegen options of a build's encoded rustflags ([`rustc_options`]),
/// in order: `k=v` or a bare `k` (no value), a name's `_` as `-` (rustc
/// looks an option up so: `-C target_feature` is `-C target-feature`), and
/// `-O` as `opt-level=3`.
pub fn codegen_options(encoded: &str) -> Vec<(String, Option<String>)> {
    let kv = |v: &str| v.split_once('=').map_or((v.replace('_', "-"), None), |(k, v)| (k.replace('_', "-"), Some(v.to_string())));
    rustc_options(encoded).into_iter().filter_map(|(c, v)| match c {
        'C' => Some(kv(&v)),
        'O' => Some(kv("opt-level=3")),
        _ => None,
    }).collect()
}

/// `-C target-cpu` and the `-C target-feature` flags of a build's encoded
/// rustflags ([`codegen_options`]): the last `target-cpu`, and every
/// `target-feature` joined by `,`.
pub fn codegen_flags(encoded: &str) -> (Option<String>, String) {
    let mut cpu = None;
    let mut feats: Vec<String> = Vec::new();
    for (k, v) in codegen_options(encoded) {
        match (k.as_str(), v) {
            ("target-cpu", Some(v)) => cpu = Some(v),
            ("target-feature", Some(v)) => feats.push(v),
            _ => {}
        }
    }
    (cpu, feats.join(","))
}

/// The builtin cfgs a build script sees (`CARGO_CFG_<NAME>`: Cargo prints
/// a bare cfg as empty and joins a name's values with commas), each with
/// whether it carries values: rustc's builtin cfgs that a stable compiler
/// shows. `target_feature` is bound apart (A-S3, its stable features).
pub const BUILD_CFGS: &[(&str, bool)] = &[("debug_assertions", false), ("panic", true), ("proc_macro", false), ("target_abi", true), ("target_arch", true), ("target_endian", true), ("target_env", true), ("target_family", true), ("target_has_atomic", true), ("target_has_atomic_primitive_alignment", true), ("target_os", true), ("target_pointer_width", true), ("target_vendor", true), ("test", false), ("unix", false), ("windows", false)];

/// rustc's builtin cfgs that only a nightly compiler shows (its
/// `GATED_CFGS`), which a stable build cannot see.
pub const NIGHTLY_CFGS: &[&str] = &["contract_checks", "fmt_debug", "overflow_checks", "relocation_model", "sanitize", "sanitizer_cfi_generalize_pointers", "sanitizer_cfi_normalize_integers", "target_has_atomic_load_store", "target_has_reliable_f128", "target_has_reliable_f128_math", "target_has_reliable_f16", "target_has_reliable_f16_math", "target_object_format", "target_thread_local", "ub_checks"];

/// Whether a build script knows the cfg `name` (bare, or with a value): a
/// builtin of [`BUILD_CFGS`] in the form Cargo shows it (the nightly adds
/// a bare `target_has_atomic`), a Cargo feature, or a cfg that is no
/// builtin at all (a `--cfg`); not `target_feature` (bound by A-S3) nor a
/// nightly-only builtin.
pub fn build_sees(name: &str, valued: bool) -> bool {
    match BUILD_CFGS.iter().find(|(n, _)| *n == name) {
        Some((_, v)) => *v == valued,
        None => name != "target_feature" && !NIGHTLY_CFGS.contains(&name),
    }
}

/// The build's cfg set as a build script knows it: its Cargo features
/// (`CARGO_CFG_FEATURE`), the builtin cfgs of [`BUILD_CFGS`]
/// (`CARGO_CFG_<NAME>`) and every `--cfg` rustc reads in its rustflags
/// (`CARGO_ENCODED_RUSTFLAGS` through [`rustc_options`]: `--cfg spec` or
/// `--cfg=spec`, not another option's value; a spec `name` or
/// `name="value"`). `Err` when the rustflags set what rustc derives the
/// configuration from where a build script cannot see the result
/// ([`rustc_options`], rustc's spellings): `-C debug-assertions`, or the
/// optimization level it follows without it (`-C opt-level`, `-O`), since
/// `CARGO_CFG_DEBUG_ASSERTIONS` follows the profile; `-C overflow-checks`,
/// the checks the MIR holds, which follow `debug_assertions` unless set
/// and which no variable shows; any `-Z` option (`ub_checks`, `fmt_debug`
/// and the other cfgs only a nightly shows follow them); an `@file`, whose
/// arguments rustc reads from the file; a `--cfg` of a builtin cfg's name
/// (of [`BUILD_CFGS`], [`NIGHTLY_CFGS`] or `target_feature`, whatever its
/// value), which rustc takes past `-A explicit_builtin_cfgs_in_flags` and
/// holds apart from the option that sets it, deriving the rest from the
/// option (`--cfg debug_assertions` in a release build: no overflow
/// checks). `-C panic` is in `CARGO_CFG_PANIC`, and A-S3 reads
/// `-C target-cpu` and `-C target-feature`.
pub fn build_cfg(get: &dyn Fn(&str) -> Option<String>) -> BuildCfg {
    let flags = get("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let args: Vec<&str> = flags.split('\x1f').collect();
    let changes = |k: &str| matches!(k, "debug-assertions" | "opt-level" | "overflow-checks");
    let set = codegen_options(&flags).into_iter().find(|(k, _)| changes(k)).map(|(k, v)| format!("-C {k}{}", v.map(|v| format!("={v}")).unwrap_or_default()));
    let set = set.or_else(|| rustc_options(&flags).into_iter().find(|(c, _)| *c == 'Z').map(|(_, v)| format!("-Z {v}")));
    if let Some(why) = set.or_else(|| args.iter().find(|a| a.starts_with('@')).map(|a| a.to_string())) {
        return Err(format!("this build's rustflags `{}` set {why}, from which rustc derives `debug_assertions`, the overflow checks or a cfg only a nightly shows where a build script cannot see the result (Cargo's variables follow the profile): set it in the profile instead", args.join(" ")));
    }
    let mut cfg = BTreeSet::new();
    for f in get("CARGO_CFG_FEATURE").unwrap_or_default().split(',').filter(|f| !f.is_empty()) {
        cfg.insert(("feature".to_string(), Some(f.to_string())));
    }
    for (n, valued) in BUILD_CFGS {
        match get(&format!("CARGO_CFG_{}", n.to_uppercase())) {
            Some(v) if *valued => cfg.extend(v.split(',').map(|x| (n.to_string(), Some(x.to_string())))),
            Some(_) => {
                cfg.insert((n.to_string(), None));
            }
            None => {}
        }
    }
    for (_, spec) in rustc_options(&flags).into_iter().filter(|(c, _)| *c == 'c') {
        let (n, v) = match spec.split_once('=') {
            Some((n, v)) => (n.trim().to_string(), Some(v.trim().trim_matches('"').to_string())),
            None => (spec.trim().to_string(), None),
        };
        if n == "target_feature" || NIGHTLY_CFGS.contains(&n.as_str()) || BUILD_CFGS.iter().any(|(b, _)| *b == n) {
            return Err(format!("this build's rustflags `{}` set the builtin cfg `{n}` by `--cfg`: rustc derives the rest of the configuration from the option that sets that cfg, not from the cfg (`--cfg debug_assertions` in a release build leaves the overflow checks off), where a build script cannot see the result: set the option or the profile instead", args.join(" ")));
        }
        cfg.insert((n, v));
    }
    Ok(cfg)
}
