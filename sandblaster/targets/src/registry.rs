//! The list of target models: names, feature requirements, instructions,
//! pseudocode references and the source items that make up each model.
//!
//! This is the table the core-text models transcribe into `DefKind::Intrinsic`
//! globals (DESIGN.md §9.2: "per intrinsic, a global whose body is a lane-level
//! transcription of the vendor pseudocode, the Rust path it prints as, and
//! its feature requirements"; the globals and their signatures are in
//! [`crate::coretext`], one per model, in the same order). It is also the key
//! of the evidence records: a
//! model's evidence is tied to the hash of the text of its [`Model::items`]
//! ([`crate::evidence::model_hash`]), so editing a model or any helper it uses
//! (a SHA helper function, a typed view, the vector type alias) invalidates
//! its evidence until the differential campaign is re-run.
#![forbid(unsafe_code)]

use std::ops::RangeInclusive;

/// Target architecture of a model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    /// `aarch64` (little-endian), NEON + FEAT_SHA256.
    Aarch64,
    /// `x86_64`: SSE2/SSSE3/SSE4.1 + SHA-NI, AVX/AVX2, AVX-512F/BW/VL/DQ,
    /// IFMA, GFNI, VBMI/VBMI2, VPOPCNTDQ, BITALG.
    X86_64,
}

impl Arch {
    /// The `target_arch` spelling (also the evidence file stem).
    pub fn name(self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
        }
    }

    /// Parse a `target_arch` spelling.
    pub fn from_name(name: &str) -> Option<Arch> {
        match name {
            "aarch64" => Some(Arch::Aarch64),
            "x86_64" => Some(Arch::X86_64),
            _ => None,
        }
    }

    /// The architecture this crate was compiled for, if it has models.
    pub fn current() -> Option<Arch> {
        if cfg!(target_arch = "aarch64") {
            Some(Arch::Aarch64)
        } else if cfg!(target_arch = "x86_64") {
            Some(Arch::X86_64)
        } else {
            None
        }
    }

    /// All models of this architecture.
    pub fn models(self) -> &'static [Model] {
        match self {
            Arch::Aarch64 => AARCH64,
            Arch::X86_64 => X86_64,
        }
    }
}

/// A model source file (embedded at compile time for hashing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// `src/aarch64/mod.rs` (vector type aliases).
    Aarch64Mod,
    /// `src/aarch64/neon.rs`.
    Neon,
    /// `src/aarch64/sha2.rs`.
    Sha2,
    /// `src/aarch64/neon2.rs` (byte/halfword/doubleword lane operations, plan O10).
    Neon2,
    /// `src/aarch64/sha3.rs` (FEAT_SHA3 / FEAT_SHA512).
    Sha3,
    /// `src/x86_64/mod.rs` (`M128i` and the typed views).
    X86Mod,
    /// `src/x86_64/sse.rs`.
    Sse,
    /// `src/x86_64/sha.rs`.
    Sha,
    /// `src/x86_64/wide.rs` (`M256i`, `M512i`, opmask types, element accessors).
    X86Wide,
    /// `src/x86_64/vec.rs` (VL-generic VEX/EVEX instruction semantics).
    X86Vec,
    /// `src/x86_64/avx512.rs` (AVX-512F/BW/VL/DQ intrinsics).
    Avx512,
    /// `src/x86_64/avx2.rs` (AVX/AVX2 intrinsics).
    Avx2,
    /// `src/x86_64/ifma.rs` (AVX512IFMA).
    Ifma,
    /// `src/x86_64/gfni.rs` (GFNI).
    Gfni,
    /// `src/x86_64/vbmi.rs` (VBMI, VBMI2, VPOPCNTDQ, BITALG).
    Vbmi,
}

impl Source {
    /// Path relative to the crate root.
    pub fn path(self) -> &'static str {
        match self {
            Source::Aarch64Mod => "src/aarch64/mod.rs",
            Source::Neon => "src/aarch64/neon.rs",
            Source::Sha2 => "src/aarch64/sha2.rs",
            Source::Neon2 => "src/aarch64/neon2.rs",
            Source::Sha3 => "src/aarch64/sha3.rs",
            Source::X86Mod => "src/x86_64/mod.rs",
            Source::Sse => "src/x86_64/sse.rs",
            Source::Sha => "src/x86_64/sha.rs",
            Source::X86Wide => "src/x86_64/wide.rs",
            Source::X86Vec => "src/x86_64/vec.rs",
            Source::Avx512 => "src/x86_64/avx512.rs",
            Source::Avx2 => "src/x86_64/avx2.rs",
            Source::Ifma => "src/x86_64/ifma.rs",
            Source::Gfni => "src/x86_64/gfni.rs",
            Source::Vbmi => "src/x86_64/vbmi.rs",
        }
    }

    /// The file's text as compiled into this crate.
    pub fn text(self) -> &'static str {
        match self {
            Source::Aarch64Mod => include_str!("aarch64/mod.rs"),
            Source::Neon => include_str!("aarch64/neon.rs"),
            Source::Sha2 => include_str!("aarch64/sha2.rs"),
            Source::Neon2 => include_str!("aarch64/neon2.rs"),
            Source::Sha3 => include_str!("aarch64/sha3.rs"),
            Source::X86Mod => include_str!("x86_64/mod.rs"),
            Source::Sse => include_str!("x86_64/sse.rs"),
            Source::Sha => include_str!("x86_64/sha.rs"),
            Source::X86Wide => include_str!("x86_64/wide.rs"),
            Source::X86Vec => include_str!("x86_64/vec.rs"),
            Source::Avx512 => include_str!("x86_64/avx512.rs"),
            Source::Avx2 => include_str!("x86_64/avx2.rs"),
            Source::Ifma => include_str!("x86_64/ifma.rs"),
            Source::Gfni => include_str!("x86_64/gfni.rs"),
            Source::Vbmi => include_str!("x86_64/vbmi.rs"),
        }
    }
}

/// One item (function or type alias) of a model's source text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Item {
    /// The file containing it.
    pub source: Source,
    /// The item's name (`pub fn NAME` or `pub type NAME`).
    pub name: &'static str,
}

const fn it(source: Source, name: &'static str) -> Item {
    Item { source, name }
}

/// One intrinsic model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    /// The stdarch intrinsic name (also the model function's name).
    pub name: &'static str,
    /// Architecture.
    pub arch: Arch,
    /// The `core::arch` path the kernel global prints as.
    pub rust_path: &'static str,
    /// Target features the intrinsic requires (before implication closure).
    pub features: &'static [&'static str],
    /// The instruction it compiles to.
    pub instruction: &'static str,
    /// Where the transcribed pseudocode comes from.
    pub pseudocode: &'static str,
    /// The accepted immediate range (tested exhaustively), if any.
    pub immediates: Option<RangeInclusive<i32>>,
    /// The source items whose text defines the model (the model function
    /// first, then its helpers and representation types).
    pub items: &'static [Item],
}

use Source::{Aarch64Mod, Avx2, Avx512, Gfni, Ifma, Neon, Neon2, Sha, Sha2, Sha3, Sse, Vbmi, X86Mod, X86Vec, X86Wide};

const ARM_ARM: &str =
    "Arm Architecture Reference Manual for A-profile (DDI 0487), A64 SIMD&FP instruction";
const ARM_SHA: &str = "Arm Architecture Reference Manual for A-profile (DDI 0487), A64 SHA256 instruction + shared/functions/crypto (SHA256hash, SHAchoose, SHAmajority, SHAhashSIGMA0/1)";
const ARM_SHA3: &str = "Arm Architecture Reference Manual for A-profile (DDI 0487), A64 SIMD&FP instruction (FEAT_SHA3 / FEAT_SHA512)";
const SDM: &str = "Intel 64 and IA-32 Architectures SDM Vol. 2, instruction Operation section";
const SDM_SHA: &str = "Intel 64 and IA-32 Architectures SDM Vol. 2, SHA extensions (Ch, Maj, Σ0, Σ1, σ0, σ1 as defined there)";

macro_rules! model {
    ($arch:ident, $name:ident, $path:literal, [$($feat:literal),*], $instr:literal, $pseudo:expr, $imm:expr, [$($src:ident :: $item:ident),* $(,)?]) => {
        Model {
            name: stringify!($name),
            arch: Arch::$arch,
            rust_path: $path,
            features: &[$($feat),*],
            instruction: $instr,
            pseudocode: $pseudo,
            immediates: $imm,
            items: &[it(model!(@src $arch), stringify!($name)) $(, it($src, stringify!($item)))*],
        }
    };
    (@src Aarch64) => { Neon };
    (@src X86_64) => { Sse };
}

/// An x86_64 model of the 256/512-bit families (MODELS.md §10): its first
/// item is the intrinsic in source file `$src`, the rest the instruction
/// model of `src/x86_64/vec.rs` (or the family file), helpers, accessors and
/// representation types it uses.
macro_rules! wide {
    ($src:ident, $name:ident, [$($feat:literal),*], $instr:literal, $imm:expr, [$($isrc:ident :: $item:ident),* $(,)?]) => {
        Model {
            name: stringify!($name),
            arch: Arch::X86_64,
            rust_path: concat!("core::arch::x86_64::", stringify!($name)),
            features: &[$($feat),*],
            instruction: $instr,
            pseudocode: SDM,
            immediates: $imm,
            items: &[it($src, stringify!($name)) $(, it($isrc, stringify!($item)))*],
        }
    };
}

/// The aarch64 SHA helper items shared by SHA256H and SHA256H2.
/// An aarch64 model whose first item is in `$src` (the O10 files).
macro_rules! a64m {
    ($src:ident, $name:ident, [$($feat:literal),*], $instr:literal, $pseudo:expr, $imm:expr, [$($isrc:ident :: $item:ident),* $(,)?]) => {
        Model {
            name: stringify!($name),
            arch: Arch::Aarch64,
            rust_path: concat!("core::arch::aarch64::", stringify!($name)),
            features: &[$($feat),*],
            instruction: $instr,
            pseudocode: $pseudo,
            immediates: $imm,
            items: &[it($src, stringify!($name)) $(, it($isrc, stringify!($item)))*],
        }
    };
}

macro_rules! sha256hash_items {
    () => {
        [
            it(Sha2, "vsha256hq_u32"),
            it(Sha2, "sha256hash"),
            it(Sha2, "sha_choose"),
            it(Sha2, "sha_majority"),
            it(Sha2, "sha_hash_sigma0"),
            it(Sha2, "sha_hash_sigma1"),
            it(Aarch64Mod, "Uint32x4"),
        ]
    };
}

/// aarch64 models (NEON + FEAT_SHA256), DESIGN.md §9.2 initial coverage.
pub static AARCH64: &[Model] = &[
    model!(
        Aarch64,
        vld1q_u8,
        "core::arch::aarch64::vld1q_u8",
        ["neon"],
        "LD1 {Vt.16B}, [Xn]",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint8x16]
    ),
    model!(
        Aarch64,
        vld1q_u32,
        "core::arch::aarch64::vld1q_u32",
        ["neon"],
        "LD1 {Vt.4S}, [Xn]",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vld1_u8,
        "core::arch::aarch64::vld1_u8",
        ["neon"],
        "LD1 {Vt.8B}, [Xn]",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint8x8]
    ),
    model!(
        Aarch64,
        vst1q_u8,
        "core::arch::aarch64::vst1q_u8",
        ["neon"],
        "ST1 {Vt.16B}, [Xn]",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint8x16]
    ),
    model!(
        Aarch64,
        vst1q_u32,
        "core::arch::aarch64::vst1q_u32",
        ["neon"],
        "ST1 {Vt.4S}, [Xn]",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vrev32q_u8,
        "core::arch::aarch64::vrev32q_u8",
        ["neon"],
        "REV32 Vd.16B, Vn.16B",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint8x16]
    ),
    model!(
        Aarch64,
        vreinterpretq_u32_u8,
        "core::arch::aarch64::vreinterpretq_u32_u8",
        ["neon"],
        "(none: register bit reinterpretation)",
        "Arm ARM: vector register bit layout (Elem[V, e, esize] = V<(e+1)*esize-1 : e*esize>)",
        None,
        [Aarch64Mod::Uint8x16, Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vreinterpretq_u8_u32,
        "core::arch::aarch64::vreinterpretq_u8_u32",
        ["neon"],
        "(none: register bit reinterpretation)",
        "Arm ARM: vector register bit layout (Elem[V, e, esize] = V<(e+1)*esize-1 : e*esize>)",
        None,
        [Aarch64Mod::Uint8x16, Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vaddq_u32,
        "core::arch::aarch64::vaddq_u32",
        ["neon"],
        "ADD Vd.4S, Vn.4S, Vm.4S",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        veorq_u32,
        "core::arch::aarch64::veorq_u32",
        ["neon"],
        "EOR Vd.16B, Vn.16B, Vm.16B",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vandq_u32,
        "core::arch::aarch64::vandq_u32",
        ["neon"],
        "AND Vd.16B, Vn.16B, Vm.16B",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vorrq_u32,
        "core::arch::aarch64::vorrq_u32",
        ["neon"],
        "ORR Vd.16B, Vn.16B, Vm.16B",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vshlq_n_u32,
        "core::arch::aarch64::vshlq_n_u32",
        ["neon"],
        "SHL Vd.4S, Vn.4S, #N",
        ARM_ARM,
        Some(0..=31),
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vshrq_n_u32,
        "core::arch::aarch64::vshrq_n_u32",
        ["neon"],
        "USHR Vd.4S, Vn.4S, #N",
        ARM_ARM,
        Some(1..=32),
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vextq_u32,
        "core::arch::aarch64::vextq_u32",
        ["neon"],
        "EXT Vd.16B, Vn.16B, Vm.16B, #(4N)",
        ARM_ARM,
        Some(0..=3),
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vdupq_n_u32,
        "core::arch::aarch64::vdupq_n_u32",
        ["neon"],
        "DUP Vd.4S, Wn",
        ARM_ARM,
        None,
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vgetq_lane_u32,
        "core::arch::aarch64::vgetq_lane_u32",
        ["neon"],
        "UMOV Wd, Vn.S[LANE]",
        ARM_ARM,
        Some(0..=3),
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vsetq_lane_u32,
        "core::arch::aarch64::vsetq_lane_u32",
        ["neon"],
        "INS Vd.S[LANE], Wn",
        ARM_ARM,
        Some(0..=3),
        [Aarch64Mod::Uint32x4]
    ),
    model!(
        Aarch64,
        vsetq_lane_u8,
        "core::arch::aarch64::vsetq_lane_u8",
        ["neon"],
        "INS Vd.B[LANE], Wn",
        ARM_ARM,
        Some(0..=15),
        [Aarch64Mod::Uint8x16]
    ),
    Model {
        name: "vsha256hq_u32",
        arch: Arch::Aarch64,
        rust_path: "core::arch::aarch64::vsha256hq_u32",
        features: &["sha2"],
        instruction: "SHA256H Qd, Qn, Vm.4S",
        pseudocode: ARM_SHA,
        immediates: None,
        items: &sha256hash_items!(),
    },
    Model {
        name: "vsha256h2q_u32",
        arch: Arch::Aarch64,
        rust_path: "core::arch::aarch64::vsha256h2q_u32",
        features: &["sha2"],
        instruction: "SHA256H2 Qd, Qn, Vm.4S",
        pseudocode: ARM_SHA,
        immediates: None,
        items: &{
            let mut items = sha256hash_items!();
            items[0] = it(Sha2, "vsha256h2q_u32");
            items
        },
    },
    Model {
        name: "vsha256su0q_u32",
        arch: Arch::Aarch64,
        rust_path: "core::arch::aarch64::vsha256su0q_u32",
        features: &["sha2"],
        instruction: "SHA256SU0 Vd.4S, Vn.4S",
        pseudocode: ARM_SHA,
        immediates: None,
        items: &[it(Sha2, "vsha256su0q_u32"), it(Aarch64Mod, "Uint32x4")],
    },
    Model {
        name: "vsha256su1q_u32",
        arch: Arch::Aarch64,
        rust_path: "core::arch::aarch64::vsha256su1q_u32",
        features: &["sha2"],
        instruction: "SHA256SU1 Vd.4S, Vn.4S, Vm.4S",
        pseudocode: ARM_SHA,
        immediates: None,
        items: &[it(Sha2, "vsha256su1q_u32"), it(Aarch64Mod, "Uint32x4")],
    },

    // ---- plan O10: NEON u8/u16/u64 and widening lane operations (src/aarch64/neon2.rs) ----
    a64m!(Neon2, vld1q_u64, ["neon"], "LD1 {Vt.2D}, [Xn]", ARM_ARM, None, [Aarch64Mod::Uint64x2]),
    a64m!(Neon2, vst1q_u64, ["neon"], "ST1 {Vt.2D}, [Xn]", ARM_ARM, None, [Aarch64Mod::Uint64x2]),
    a64m!(Neon2, veorq_u8, ["neon"], "EOR Vd.16B, Vn.16B, Vm.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vandq_u8, ["neon"], "AND Vd.16B, Vn.16B, Vm.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vorrq_u8, ["neon"], "ORR Vd.16B, Vn.16B, Vm.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vdupq_n_u8, ["neon"], "DUP Vd.16B, Wn", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vshrq_n_u8, ["neon"], "USHR Vd.16B, Vn.16B, #N", ARM_ARM, Some(1..=8), [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vcltq_u8, ["neon"], "CMHI Vd.16B, Vm.16B, Vn.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vcgeq_u8, ["neon"], "CMHS Vd.16B, Vn.16B, Vm.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vceqq_u8, ["neon"], "CMEQ Vd.16B, Vn.16B, Vm.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vqtbl1q_u8, ["neon"], "TBL Vd.16B, {Vn.16B}, Vm.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vcntq_u8, ["neon"], "CNT Vd.16B, Vn.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vaddvq_u8, ["neon"], "ADDV Bd, Vn.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vmaxvq_u8, ["neon"], "UMAXV Bd, Vn.16B", ARM_ARM, None, [Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vreinterpretq_u16_u8, ["neon"], "(none: register bit reinterpretation)", ARM_ARM, None, [Aarch64Mod::Uint8x16, Aarch64Mod::Uint16x8]),
    a64m!(Neon2, vreinterpretq_u64_u8, ["neon"], "(none: register bit reinterpretation)", ARM_ARM, None, [Aarch64Mod::Uint8x16, Aarch64Mod::Uint64x2]),
    a64m!(Neon2, vcombine_u8, ["neon"], "INS Vd.D[1], Vm.D[0] (high half)", ARM_ARM, None, [Aarch64Mod::Uint8x8, Aarch64Mod::Uint8x16]),
    a64m!(Neon2, vgetq_lane_u64, ["neon"], "UMOV Xd, Vn.D[LANE]", ARM_ARM, Some(0..=1), [Aarch64Mod::Uint64x2]),
    a64m!(Neon2, vshrn_n_u16, ["neon"], "SHRN Vd.8B, Vn.8H, #N", ARM_ARM, Some(1..=8), [Aarch64Mod::Uint16x8, Aarch64Mod::Uint8x8]),
    a64m!(Neon2, vshrn_n_u64, ["neon"], "SHRN Vd.2S, Vn.2D, #N", ARM_ARM, Some(1..=32), [Aarch64Mod::Uint64x2, Aarch64Mod::Uint32x2]),
    a64m!(Neon2, vmovn_u64, ["neon"], "XTN Vd.2S, Vn.2D", ARM_ARM, None, [Aarch64Mod::Uint64x2, Aarch64Mod::Uint32x2]),
    a64m!(Neon2, vaddq_u64, ["neon"], "ADD Vd.2D, Vn.2D, Vm.2D", ARM_ARM, None, [Aarch64Mod::Uint64x2]),
    a64m!(Neon2, vsraq_n_u64, ["neon"], "USRA Vd.2D, Vn.2D, #N", ARM_ARM, Some(1..=64), [Aarch64Mod::Uint64x2]),
    a64m!(Neon2, vbslq_u64, ["neon"], "BSL Vd.16B, Vn.16B, Vm.16B", ARM_ARM, None, [Aarch64Mod::Uint64x2]),
    a64m!(Neon2, vbslq_u32, ["neon"], "BSL Vd.16B, Vn.16B, Vm.16B", ARM_ARM, None, [Aarch64Mod::Uint32x4]),
    a64m!(Neon2, vmull_u32, ["neon"], "UMULL Vd.2D, Vn.2S, Vm.2S", ARM_ARM, None, [Aarch64Mod::Uint32x2, Aarch64Mod::Uint64x2]),
    a64m!(Neon2, vmlal_u32, ["neon"], "UMLAL Vd.2D, Vn.2S, Vm.2S", ARM_ARM, None, [Aarch64Mod::Uint64x2, Aarch64Mod::Uint32x2]),
    // ---- FEAT_SHA3 / FEAT_SHA512 (src/aarch64/sha3.rs), rustc feature `sha3` ----
    a64m!(Sha3, veor3q_u8, ["sha3"], "EOR3 Vd.16B, Vn.16B, Vm.16B, Va.16B", ARM_SHA3, None, [Aarch64Mod::Uint8x16]),
    a64m!(Sha3, vbcaxq_u8, ["sha3"], "BCAX Vd.16B, Vn.16B, Vm.16B, Va.16B", ARM_SHA3, None, [Aarch64Mod::Uint8x16]),
    a64m!(Sha3, vrax1q_u64, ["sha3"], "RAX1 Vd.2D, Vn.2D, Vm.2D", ARM_SHA3, None, [Aarch64Mod::Uint64x2]),
    a64m!(Sha3, vxarq_u64, ["sha3"], "XAR Vd.2D, Vn.2D, Vm.2D, #IMM6", ARM_SHA3, Some(0..=63), [Aarch64Mod::Uint64x2]),
    a64m!(Sha3, vsha512hq_u64, ["sha3"], "SHA512H Qd, Qn, Vm.2D", ARM_SHA3, None, [Sha3::sha512_sigma1, Aarch64Mod::Uint64x2]),
    a64m!(Sha3, vsha512h2q_u64, ["sha3"], "SHA512H2 Qd, Qn, Vm.2D", ARM_SHA3, None, [Sha3::sha512_sigma0, Aarch64Mod::Uint64x2]),
    a64m!(Sha3, vsha512su0q_u64, ["sha3"], "SHA512SU0 Vd.2D, Vn.2D", ARM_SHA3, None, [Aarch64Mod::Uint64x2]),
    a64m!(Sha3, vsha512su1q_u64, ["sha3"], "SHA512SU1 Vd.2D, Vn.2D, Vm.2D", ARM_SHA3, None, [Aarch64Mod::Uint64x2]),
];

/// x86_64 models: SSE2/SSSE3/SSE4.1 + SHA-NI (DESIGN.md §9.2 initial coverage,
/// the first [`ROUND0_X86_64`]), then the AVX-512F/BW/VL/DQ, IFMA, GFNI,
/// VBMI/VBMI2, VPOPCNTDQ/BITALG and AVX2 models (design §13.4).
pub static X86_64: &[Model] = &[
    model!(
        X86_64,
        _mm_loadu_si128,
        "core::arch::x86_64::_mm_loadu_si128",
        ["sse2"],
        "MOVDQU xmm1, m128",
        SDM,
        None,
        [X86Mod::M128i]
    ),
    model!(
        X86_64,
        _mm_storeu_si128,
        "core::arch::x86_64::_mm_storeu_si128",
        ["sse2"],
        "MOVDQU m128, xmm1",
        SDM,
        None,
        [X86Mod::M128i]
    ),
    model!(
        X86_64,
        _mm_shuffle_epi8,
        "core::arch::x86_64::_mm_shuffle_epi8",
        ["ssse3"],
        "PSHUFB xmm1, xmm2/m128",
        SDM,
        None,
        [X86Mod::M128i]
    ),
    model!(
        X86_64,
        _mm_shuffle_epi32,
        "core::arch::x86_64::_mm_shuffle_epi32",
        ["sse2"],
        "PSHUFD xmm1, xmm2/m128, imm8",
        SDM,
        Some(0..=255),
        [X86Mod::M128i, X86Mod::view_u32, X86Mod::from_u32x4]
    ),
    model!(
        X86_64,
        _mm_alignr_epi8,
        "core::arch::x86_64::_mm_alignr_epi8",
        ["ssse3"],
        "PALIGNR xmm1, xmm2/m128, imm8",
        SDM,
        Some(0..=255),
        [X86Mod::M128i]
    ),
    model!(
        X86_64,
        _mm_blend_epi16,
        "core::arch::x86_64::_mm_blend_epi16",
        ["sse4.1"],
        "PBLENDW xmm1, xmm2/m128, imm8",
        SDM,
        Some(0..=255),
        [X86Mod::M128i, X86Mod::view_u16, X86Mod::from_u16x8]
    ),
    model!(
        X86_64,
        _mm_add_epi32,
        "core::arch::x86_64::_mm_add_epi32",
        ["sse2"],
        "PADDD xmm1, xmm2/m128",
        SDM,
        None,
        [X86Mod::M128i, X86Mod::view_u32, X86Mod::from_u32x4]
    ),
    model!(
        X86_64,
        _mm_set_epi32,
        "core::arch::x86_64::_mm_set_epi32",
        ["sse2"],
        "(composite: MOVD/PUNPCK* or a constant load)",
        "Intel Intrinsics Guide: _mm_set_epi32 Operation",
        None,
        [X86Mod::M128i, X86Mod::from_u32x4]
    ),
    model!(
        X86_64,
        _mm_set_epi64x,
        "core::arch::x86_64::_mm_set_epi64x",
        ["sse2"],
        "(composite: MOVQ/PUNPCKLQDQ or a constant load)",
        "Intel Intrinsics Guide: _mm_set_epi64x Operation",
        None,
        [X86Mod::M128i, X86Mod::from_u64x2]
    ),
    model!(
        X86_64,
        _mm_xor_si128,
        "core::arch::x86_64::_mm_xor_si128",
        ["sse2"],
        "PXOR xmm1, xmm2/m128",
        SDM,
        None,
        [X86Mod::M128i]
    ),
    model!(
        X86_64,
        _mm_and_si128,
        "core::arch::x86_64::_mm_and_si128",
        ["sse2"],
        "PAND xmm1, xmm2/m128",
        SDM,
        None,
        [X86Mod::M128i]
    ),
    model!(
        X86_64,
        _mm_or_si128,
        "core::arch::x86_64::_mm_or_si128",
        ["sse2"],
        "POR xmm1, xmm2/m128",
        SDM,
        None,
        [X86Mod::M128i]
    ),
    Model {
        name: "_mm_sha256rnds2_epu32",
        arch: Arch::X86_64,
        rust_path: "core::arch::x86_64::_mm_sha256rnds2_epu32",
        features: &["sha"],
        instruction: "SHA256RNDS2 xmm1, xmm2/m128, <XMM0>",
        pseudocode: SDM_SHA,
        immediates: None,
        items: &[
            it(Sha, "_mm_sha256rnds2_epu32"),
            it(Sha, "sdm_ch"),
            it(Sha, "sdm_maj"),
            it(Sha, "sdm_big_sigma0"),
            it(Sha, "sdm_big_sigma1"),
            it(X86Mod, "M128i"),
            it(X86Mod, "view_u32"),
            it(X86Mod, "from_u32x4"),
        ],
    },
    Model {
        name: "_mm_sha256msg1_epu32",
        arch: Arch::X86_64,
        rust_path: "core::arch::x86_64::_mm_sha256msg1_epu32",
        features: &["sha"],
        instruction: "SHA256MSG1 xmm1, xmm2/m128",
        pseudocode: SDM_SHA,
        immediates: None,
        items: &[
            it(Sha, "_mm_sha256msg1_epu32"),
            it(Sha, "sdm_small_sigma0"),
            it(X86Mod, "M128i"),
            it(X86Mod, "view_u32"),
            it(X86Mod, "from_u32x4"),
        ],
    },
    Model {
        name: "_mm_sha256msg2_epu32",
        arch: Arch::X86_64,
        rust_path: "core::arch::x86_64::_mm_sha256msg2_epu32",
        features: &["sha"],
        instruction: "SHA256MSG2 xmm1, xmm2/m128",
        pseudocode: SDM_SHA,
        immediates: None,
        items: &[
            it(Sha, "_mm_sha256msg2_epu32"),
            it(Sha, "sdm_small_sigma1"),
            it(X86Mod, "M128i"),
            it(X86Mod, "view_u32"),
            it(X86Mod, "from_u32x4"),
        ],
    },
    // -- 256/512-bit families (MODELS.md §10), appended after the round-0
    // models so their positions (and the tests indexing them) are unchanged.
    wide!(Avx512, _mm512_loadu_si512, ["avx512f"], "VMOVDQU32 zmm1, m512", None, [X86Vec::vmovdqu, X86Wide::M512i]),
    wide!(Avx512, _mm512_storeu_si512, ["avx512f"], "VMOVDQU32 m512, zmm1", None, [X86Vec::vmovdqu, X86Wide::M512i]),
    wide!(Avx512, _mm512_add_epi32, ["avx512f"], "VPADDD zmm1, zmm2, zmm3/m512", None, [X86Vec::vpaddd, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_add_epi64, ["avx512f"], "VPADDQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpaddq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_sub_epi32, ["avx512f"], "VPSUBD zmm1, zmm2, zmm3/m512", None, [X86Vec::vpsubd, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_sub_epi64, ["avx512f"], "VPSUBQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpsubq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_xor_si512, ["avx512f"], "VPXORD zmm1, zmm2, zmm3/m512", None, [X86Vec::vpxord, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_and_si512, ["avx512f"], "VPANDD zmm1, zmm2, zmm3/m512", None, [X86Vec::vpandd, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_or_si512, ["avx512f"], "VPORD zmm1, zmm2, zmm3/m512", None, [X86Vec::vpord, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_andnot_si512, ["avx512f"], "VPANDND zmm1, zmm2, zmm3/m512", None, [X86Vec::vpandnd, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_ternarylogic_epi32, ["avx512f"], "VPTERNLOGD zmm1, zmm2, zmm3/m512, imm8", Some(0..=255), [X86Vec::vpternlogd, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_ternarylogic_epi64, ["avx512f"], "VPTERNLOGQ zmm1, zmm2, zmm3/m512, imm8", Some(0..=255), [X86Vec::vpternlogq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_rol_epi32, ["avx512f"], "VPROLD zmm1, zmm2/m512, imm8", Some(0..=255), [X86Vec::vprold, X86Vec::left_rotate_dwords, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_ror_epi32, ["avx512f"], "VPRORD zmm1, zmm2/m512, imm8", Some(0..=255), [X86Vec::vprord, X86Vec::right_rotate_dwords, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_rol_epi64, ["avx512f"], "VPROLQ zmm1, zmm2/m512, imm8", Some(0..=255), [X86Vec::vprolq, X86Vec::left_rotate_qwords, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_ror_epi64, ["avx512f"], "VPRORQ zmm1, zmm2/m512, imm8", Some(0..=255), [X86Vec::vprorq, X86Vec::right_rotate_qwords, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_rolv_epi32, ["avx512f"], "VPROLVD zmm1, zmm2, zmm3/m512", None, [X86Vec::vprolvd, X86Vec::left_rotate_dwords, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_rorv_epi32, ["avx512f"], "VPRORVD zmm1, zmm2, zmm3/m512", None, [X86Vec::vprorvd, X86Vec::right_rotate_dwords, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_rolv_epi64, ["avx512f"], "VPROLVQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vprolvq, X86Vec::left_rotate_qwords, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_rorv_epi64, ["avx512f"], "VPRORVQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vprorvq, X86Vec::right_rotate_qwords, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_slli_epi32, ["avx512f"], "VPSLLD zmm1, zmm2/m512, imm8", Some(0..=255), [X86Vec::vpslld_imm, X86Vec::logical_left_shift_dwords1, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_srli_epi32, ["avx512f"], "VPSRLD zmm1, zmm2/m512, imm8", Some(0..=255), [X86Vec::vpsrld_imm, X86Vec::logical_right_shift_dwords1, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_slli_epi64, ["avx512f"], "VPSLLQ zmm1, zmm2/m512, imm8", Some(0..=255), [X86Vec::vpsllq_imm, X86Vec::logical_left_shift_qwords1, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_srli_epi64, ["avx512f"], "VPSRLQ zmm1, zmm2/m512, imm8", Some(0..=255), [X86Vec::vpsrlq_imm, X86Vec::logical_right_shift_qwords1, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_sllv_epi64, ["avx512f"], "VPSLLVQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpsllvq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_srlv_epi64, ["avx512f"], "VPSRLVQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpsrlvq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_shuffle_epi8, ["avx512bw"], "VPSHUFB zmm1, zmm2, zmm3/m512", None, [X86Vec::vpshufb, X86Wide::M512i]),
    wide!(Avx512, _mm512_permutexvar_epi32, ["avx512f"], "VPERMD zmm1, zmm2, zmm3/m512", None, [X86Vec::vpermd, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_permutexvar_epi64, ["avx512f"], "VPERMQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpermq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_permutex2var_epi64, ["avx512f"], "VPERMI2Q zmm1, zmm2, zmm3/m512 (or VPERMT2Q)", None, [X86Vec::vpermi2q, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_shuffle_i32x4, ["avx512f"], "VSHUFI32X4 zmm1, zmm2, zmm3/m512, imm8", Some(0..=255), [X86Vec::vshufi32x4, X86Vec::vshuf128x4_tmp, X86Vec::select4, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_shuffle_i64x2, ["avx512f"], "VSHUFI64X2 zmm1, zmm2, zmm3/m512, imm8", Some(0..=255), [X86Vec::vshufi64x2, X86Vec::vshuf128x4_tmp, X86Vec::select4, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_unpacklo_epi32, ["avx512f"], "VPUNPCKLDQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpunpckldq, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_unpackhi_epi32, ["avx512f"], "VPUNPCKHDQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpunpckhdq, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_unpacklo_epi64, ["avx512f"], "VPUNPCKLQDQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpunpcklqdq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_unpackhi_epi64, ["avx512f"], "VPUNPCKHQDQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpunpckhqdq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_set1_epi32, ["avx512f"], "(composite: VPBROADCASTD zmm1, r32)", None, [X86Vec::vpbroadcastd, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Avx512, _mm512_set1_epi64, ["avx512f"], "(composite: VPBROADCASTQ zmm1, r64)", None, [X86Vec::vpbroadcastq, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_mask_blend_epi32, ["avx512f"], "VPBLENDMD zmm1 {k1}, zmm2, zmm3/m512", None, [X86Vec::vpblendmd, X86Wide::mask_bit, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i, X86Wide::Mmask16]),
    wide!(Avx512, _mm512_mask_blend_epi64, ["avx512f"], "VPBLENDMQ zmm1 {k1}, zmm2, zmm3/m512", None, [X86Vec::vpblendmq, X86Wide::mask_bit, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i, X86Wide::Mmask8]),
    wide!(Avx512, _mm512_cmplt_epu64_mask, ["avx512f"], "VPCMPUQ k1, zmm2, zmm3/m512, 1", None, [X86Vec::vpcmpuq_lt, X86Wide::qword, X86Wide::M512i, X86Wide::Mmask8]),
    wide!(Avx512, _mm512_cmpeq_epi64_mask, ["avx512f"], "VPCMPEQQ k1, zmm2, zmm3/m512", None, [X86Vec::vpcmpeqq, X86Wide::qword, X86Wide::M512i, X86Wide::Mmask8]),
    wide!(Avx512, _mm512_cmpeq_epi32_mask, ["avx512f"], "VPCMPEQD k1, zmm2, zmm3/m512", None, [X86Vec::vpcmpeqd, X86Wide::dword, X86Wide::M512i, X86Wide::Mmask16]),
    wide!(Avx512, _mm512_maskz_mov_epi32, ["avx512f"], "VMOVDQA32 zmm1 {k1}{z}, zmm2", None, [X86Vec::vmovdqa32_masked, X86Wide::mask_bit, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i, X86Wide::Mmask16]),
    wide!(Avx512, _mm512_mask_mov_epi32, ["avx512f"], "VMOVDQA32 zmm1 {k1}, zmm2", None, [X86Vec::vmovdqa32_masked, X86Wide::mask_bit, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i, X86Wide::Mmask16]),
    wide!(Avx512, _mm512_maskz_mov_epi64, ["avx512f"], "VMOVDQA64 zmm1 {k1}{z}, zmm2", None, [X86Vec::vmovdqa64_masked, X86Wide::mask_bit, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i, X86Wide::Mmask8]),
    wide!(Avx512, _mm512_mask_mov_epi64, ["avx512f"], "VMOVDQA64 zmm1 {k1}, zmm2", None, [X86Vec::vmovdqa64_masked, X86Wide::mask_bit, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i, X86Wide::Mmask8]),
    wide!(Avx512, _mm512_mullo_epi64, ["avx512dq"], "VPMULLQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpmullq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm512_mul_epu32, ["avx512f"], "VPMULUDQ zmm1, zmm2, zmm3/m512", None, [X86Vec::vpmuludq, X86Wide::dword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Avx512, _mm256_ternarylogic_epi32, ["avx512f", "avx512vl"], "VPTERNLOGD ymm1, ymm2, ymm3/m256, imm8", Some(0..=255), [X86Vec::vpternlogd, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx512, _mm256_ternarylogic_epi64, ["avx512f", "avx512vl"], "VPTERNLOGQ ymm1, ymm2, ymm3/m256, imm8", Some(0..=255), [X86Vec::vpternlogq, X86Wide::qword, X86Wide::set_qword, X86Wide::M256i]),
    wide!(Avx512, _mm256_rol_epi32, ["avx512f", "avx512vl"], "VPROLD ymm1, ymm2/m256, imm8", Some(0..=255), [X86Vec::vprold, X86Vec::left_rotate_dwords, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx512, _mm256_ror_epi32, ["avx512f", "avx512vl"], "VPRORD ymm1, ymm2/m256, imm8", Some(0..=255), [X86Vec::vprord, X86Vec::right_rotate_dwords, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx512, _mm256_rol_epi64, ["avx512f", "avx512vl"], "VPROLQ ymm1, ymm2/m256, imm8", Some(0..=255), [X86Vec::vprolq, X86Vec::left_rotate_qwords, X86Wide::qword, X86Wide::set_qword, X86Wide::M256i]),
    wide!(Avx512, _mm256_ror_epi64, ["avx512f", "avx512vl"], "VPRORQ ymm1, ymm2/m256, imm8", Some(0..=255), [X86Vec::vprorq, X86Vec::right_rotate_qwords, X86Wide::qword, X86Wide::set_qword, X86Wide::M256i]),
    wide!(Ifma, _mm512_madd52lo_epu64, ["avx512ifma"], "VPMADD52LUQ zmm1, zmm2, zmm3/m512", None, [Ifma::vpmadd52luq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Ifma, _mm512_madd52hi_epu64, ["avx512ifma"], "VPMADD52HUQ zmm1, zmm2, zmm3/m512", None, [Ifma::vpmadd52huq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Ifma, _mm256_madd52lo_epu64, ["avx512ifma", "avx512vl"], "VPMADD52LUQ ymm1, ymm2, ymm3/m256", None, [Ifma::vpmadd52luq, X86Wide::qword, X86Wide::set_qword, X86Wide::M256i]),
    wide!(Ifma, _mm256_madd52hi_epu64, ["avx512ifma", "avx512vl"], "VPMADD52HUQ ymm1, ymm2, ymm3/m256", None, [Ifma::vpmadd52huq, X86Wide::qword, X86Wide::set_qword, X86Wide::M256i]),
    wide!(Gfni, _mm512_gf2p8mul_epi8, ["gfni", "avx512f"], "VGF2P8MULB zmm1, zmm2, zmm3/m512", None, [Gfni::vgf2p8mulb, Gfni::gf2p8mul_byte, X86Wide::M512i]),
    wide!(Gfni, _mm256_gf2p8mul_epi8, ["gfni", "avx"], "VGF2P8MULB ymm1, ymm2, ymm3/m256", None, [Gfni::vgf2p8mulb, Gfni::gf2p8mul_byte, X86Wide::M256i]),
    wide!(Gfni, _mm_gf2p8mul_epi8, ["gfni"], "GF2P8MULB xmm1, xmm2/m128", None, [Gfni::vgf2p8mulb, Gfni::gf2p8mul_byte, X86Mod::M128i]),
    wide!(Gfni, _mm512_gf2p8affine_epi64_epi8, ["gfni", "avx512f"], "VGF2P8AFFINEQB zmm1, zmm2, zmm3/m512, imm8", Some(0..=255), [Gfni::vgf2p8affineqb, Gfni::affine_byte, Gfni::parity, X86Wide::qword, X86Wide::M512i]),
    wide!(Gfni, _mm256_gf2p8affine_epi64_epi8, ["gfni", "avx"], "VGF2P8AFFINEQB ymm1, ymm2, ymm3/m256, imm8", Some(0..=255), [Gfni::vgf2p8affineqb, Gfni::affine_byte, Gfni::parity, X86Wide::qword, X86Wide::M256i]),
    wide!(Gfni, _mm_gf2p8affine_epi64_epi8, ["gfni"], "GF2P8AFFINEQB xmm1, xmm2/m128, imm8", Some(0..=255), [Gfni::vgf2p8affineqb, Gfni::affine_byte, Gfni::parity, X86Wide::qword, X86Mod::M128i]),
    wide!(Gfni, _mm512_gf2p8affineinv_epi64_epi8, ["gfni", "avx512f"], "VGF2P8AFFINEINVQB zmm1, zmm2, zmm3/m512, imm8", Some(0..=255), [Gfni::vgf2p8affineinvqb, Gfni::affine_inverse_byte, Gfni::inverse, Gfni::gf2p8mul_byte, Gfni::parity, X86Wide::qword, X86Wide::M512i]),
    wide!(Gfni, _mm256_gf2p8affineinv_epi64_epi8, ["gfni", "avx"], "VGF2P8AFFINEINVQB ymm1, ymm2, ymm3/m256, imm8", Some(0..=255), [Gfni::vgf2p8affineinvqb, Gfni::affine_inverse_byte, Gfni::inverse, Gfni::gf2p8mul_byte, Gfni::parity, X86Wide::qword, X86Wide::M256i]),
    wide!(Gfni, _mm_gf2p8affineinv_epi64_epi8, ["gfni"], "GF2P8AFFINEINVQB xmm1, xmm2/m128, imm8", Some(0..=255), [Gfni::vgf2p8affineinvqb, Gfni::affine_inverse_byte, Gfni::inverse, Gfni::gf2p8mul_byte, Gfni::parity, X86Wide::qword, X86Mod::M128i]),
    wide!(Vbmi, _mm512_permutexvar_epi8, ["avx512vbmi"], "VPERMB zmm1, zmm2, zmm3/m512", None, [Vbmi::vpermb, X86Wide::M512i]),
    wide!(Vbmi, _mm512_permutex2var_epi8, ["avx512vbmi"], "VPERMI2B zmm1, zmm2, zmm3/m512 (or VPERMT2B)", None, [Vbmi::vpermi2b, X86Wide::M512i]),
    wide!(Vbmi, _mm512_multishift_epi64_epi8, ["avx512vbmi"], "VPMULTISHIFTQB zmm1, zmm2, zmm3/m512", None, [Vbmi::vpmultishiftqb, X86Wide::qword, X86Wide::M512i]),
    wide!(Vbmi, _mm512_shldv_epi64, ["avx512vbmi2"], "VPSHLDVQ zmm1, zmm2, zmm3/m512", None, [Vbmi::vpshldvq, Vbmi::concat_qwords, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Vbmi, _mm512_shrdv_epi64, ["avx512vbmi2"], "VPSHRDVQ zmm1, zmm2, zmm3/m512", None, [Vbmi::vpshrdvq, Vbmi::concat_qwords, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Vbmi, _mm512_shldv_epi32, ["avx512vbmi2"], "VPSHLDVD zmm1, zmm2, zmm3/m512", None, [Vbmi::vpshldvd, Vbmi::concat_dwords, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Vbmi, _mm512_shrdv_epi32, ["avx512vbmi2"], "VPSHRDVD zmm1, zmm2, zmm3/m512", None, [Vbmi::vpshrdvd, Vbmi::concat_dwords, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Vbmi, _mm512_shldi_epi64, ["avx512vbmi2"], "VPSHLDQ zmm1, zmm2, zmm3/m512, imm8", Some(0..=255), [Vbmi::vpshldq_imm, Vbmi::concat_qwords, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Vbmi, _mm512_shldi_epi32, ["avx512vbmi2"], "VPSHLDD zmm1, zmm2, zmm3/m512, imm8", Some(0..=255), [Vbmi::vpshldd_imm, Vbmi::concat_dwords, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Vbmi, _mm512_popcnt_epi64, ["avx512vpopcntdq"], "VPOPCNTQ zmm1, zmm2/m512", None, [Vbmi::vpopcntq, X86Wide::qword, X86Wide::set_qword, X86Wide::M512i]),
    wide!(Vbmi, _mm512_popcnt_epi32, ["avx512vpopcntdq"], "VPOPCNTD zmm1, zmm2/m512", None, [Vbmi::vpopcntd, X86Wide::dword, X86Wide::set_dword, X86Wide::M512i]),
    wide!(Vbmi, _mm512_popcnt_epi8, ["avx512bitalg"], "VPOPCNTB zmm1, zmm2/m512", None, [Vbmi::vpopcntb, X86Wide::M512i]),
    wide!(Vbmi, _mm512_popcnt_epi16, ["avx512bitalg"], "VPOPCNTW zmm1, zmm2/m512", None, [Vbmi::vpopcntw, X86Wide::word, X86Wide::set_word, X86Wide::M512i]),
    wide!(Avx2, _mm256_loadu_si256, ["avx"], "VMOVDQU ymm1, m256", None, [X86Vec::vmovdqu, X86Wide::M256i]),
    wide!(Avx2, _mm256_storeu_si256, ["avx"], "VMOVDQU m256, ymm1", None, [X86Vec::vmovdqu, X86Wide::M256i]),
    wide!(Avx2, _mm256_add_epi32, ["avx2"], "VPADDD ymm1, ymm2, ymm3/m256", None, [X86Vec::vpaddd, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx2, _mm256_add_epi64, ["avx2"], "VPADDQ ymm1, ymm2, ymm3/m256", None, [X86Vec::vpaddq, X86Wide::qword, X86Wide::set_qword, X86Wide::M256i]),
    wide!(Avx2, _mm256_xor_si256, ["avx2"], "VPXOR ymm1, ymm2, ymm3/m256", None, [X86Vec::vpxord, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx2, _mm256_and_si256, ["avx2"], "VPAND ymm1, ymm2, ymm3/m256", None, [X86Vec::vpandd, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx2, _mm256_or_si256, ["avx2"], "VPOR ymm1, ymm2, ymm3/m256", None, [X86Vec::vpord, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx2, _mm256_shuffle_epi8, ["avx2"], "VPSHUFB ymm1, ymm2, ymm3/m256", None, [X86Vec::vpshufb, X86Wide::M256i]),
    wide!(Avx2, _mm256_permutevar8x32_epi32, ["avx2"], "VPERMD ymm1, ymm2, ymm3/m256", None, [X86Vec::vpermd, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx2, _mm256_slli_epi32, ["avx2"], "VPSLLD ymm1, ymm2, imm8", Some(0..=255), [X86Vec::vpslld_imm, X86Vec::logical_left_shift_dwords1, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx2, _mm256_srli_epi32, ["avx2"], "VPSRLD ymm1, ymm2, imm8", Some(0..=255), [X86Vec::vpsrld_imm, X86Vec::logical_right_shift_dwords1, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx2, _mm256_slli_epi64, ["avx2"], "VPSLLQ ymm1, ymm2, imm8", Some(0..=255), [X86Vec::vpsllq_imm, X86Vec::logical_left_shift_qwords1, X86Wide::qword, X86Wide::set_qword, X86Wide::M256i]),
    wide!(Avx2, _mm256_srli_epi64, ["avx2"], "VPSRLQ ymm1, ymm2, imm8", Some(0..=255), [X86Vec::vpsrlq_imm, X86Vec::logical_right_shift_qwords1, X86Wide::qword, X86Wide::set_qword, X86Wide::M256i]),
    wide!(Avx2, _mm256_blend_epi32, ["avx2"], "VPBLENDD ymm1, ymm2, ymm3/m256, imm8", Some(0..=255), [X86Vec::vpblendd, X86Wide::dword, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx2, _mm256_alignr_epi8, ["avx2"], "VPALIGNR ymm1, ymm2, ymm3/m256, imm8", Some(0..=255), [X86Vec::vpalignr256, X86Wide::M256i]),
    wide!(Avx2, _mm256_set1_epi32, ["avx"], "(composite: VPBROADCASTD ymm / VMOVD + VPSHUFD)", None, [X86Vec::vpbroadcastd, X86Wide::set_dword, X86Wide::M256i]),
    wide!(Avx2, _mm256_set1_epi64x, ["avx"], "(composite: VPBROADCASTQ ymm / VMOVQ + VPUNPCKLQDQ)", None, [X86Vec::vpbroadcastq, X86Wide::set_qword, X86Wide::M256i]),
];

/// The number of x86_64 models validated in AVX-512 host round 0 (the
/// SSE/SSSE3/SSE4.1 and SHA-NI models, `X86_64[..ROUND0_X86_64]`); the 256/512-bit
/// families follow them.
pub const ROUND0_X86_64: usize = 15;

/// The number of aarch64 models before plan O10 (NEON u8/u32 data movement
/// and lane operations, SHA2); the O10 NEON/SHA3/SHA512 models follow them.
pub const ROUND0_AARCH64: usize = 23;

/// Look a model up by architecture and name.
pub fn find(arch: Arch, name: &str) -> Option<&'static Model> {
    arch.models().iter().find(|m| m.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every model's hashed items are closed under reference: any `pub fn`
    /// or `pub type` of the model source files named in an item's text is
    /// itself an item of the model, so the source hash covers everything the
    /// model computes with (fail closed on a forgotten helper).
    #[test]
    fn items_are_closed_under_reference() {
        use crate::evidence::{item_text, tokens};
        let x86_sources = [
            Source::X86Mod,
            Source::Sse,
            Source::Sha,
            Source::X86Wide,
            Source::X86Vec,
            Source::Avx512,
            Source::Avx2,
            Source::Ifma,
            Source::Gfni,
            Source::Vbmi,
        ];
        let defined: Vec<(Source, String)> = x86_sources
            .iter()
            .flat_map(|&src| {
                tokens(src.text())
                    .windows(3)
                    .filter(|w| w[0] == "pub" && (w[1] == "fn" || w[1] == "type"))
                    .map(|w| (src, w[2].to_string()))
                    .collect::<Vec<_>>()
            })
            .collect();
        for m in X86_64 {
            for item in m.items {
                let text = item_text(item.source.text(), item.name).expect("item exists");
                for tok in tokens(text).into_iter().skip(3) {
                    if let Some((src, _)) = defined.iter().find(|(_, n)| n == tok) {
                        assert!(
                            m.items.iter().any(|i| i.name == tok),
                            "{}: item {} uses {tok} ({}) which is not among its hashed items",
                            m.name,
                            item.name,
                            src.path()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn names_are_unique_and_items_start_with_the_model() {
        for arch in [Arch::Aarch64, Arch::X86_64] {
            let models = arch.models();
            for (i, m) in models.iter().enumerate() {
                assert_eq!(m.arch, arch);
                assert_eq!(
                    m.items[0].name, m.name,
                    "first item of {} must be the model itself",
                    m.name
                );
                assert!(m.rust_path.ends_with(m.name));
                assert!(
                    models[..i].iter().all(|o| o.name != m.name),
                    "duplicate model {}",
                    m.name
                );
            }
            assert_eq!(Arch::from_name(arch.name()), Some(arch));
        }
        assert_eq!(AARCH64.len(), ROUND0_AARCH64 + 35);
        assert_eq!(AARCH64[ROUND0_AARCH64 - 1].name, "vsha256su1q_u32");
        assert_eq!(X86_64.len(), ROUND0_X86_64 + 98);
        assert_eq!(X86_64[ROUND0_X86_64 - 1].name, "_mm_sha256msg2_epu32");
        // Every wide model's source items name its representation type.
        for m in &X86_64[ROUND0_X86_64..] {
            assert!(
                m.items.iter().any(|i| matches!(i.name, "M512i" | "M256i" | "M128i")),
                "{} lacks its vector type item",
                m.name
            );
        }
    }
}
