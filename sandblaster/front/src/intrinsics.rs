//! The target-intrinsic table of the front end (DESIGN.md §9.2, §9.3).
//!
//! This is the *surface* view of the target semantics library: for every
//! intrinsic user code may name through `core::arch::aarch64` /
//! `core::arch::x86_64` it records
//!
//! * the Rust name and absolute path it prints as,
//! * the architecture and the **feature requirements** (checked against the
//!   calling function's feature set, §9.3),
//! * the HIR signature (vector types are [`Ty::Vector`]),
//! * the literal `i32` const-generic immediates with rustc's accepted range
//!   (`static_assert_uimm_bits!` etc.). Immediates may be written as turbofish
//!   (`vshlq_n_u32::<3>(a)`) or in stdarch's legacy position after the value
//!   arguments (`_mm_shuffle_epi32(a, 0x0E)`); the canonical printer always
//!   uses the turbofish.
//!
//! Pointer-taking loads/stores (`vld1q_u8`, `_mm_loadu_si128`, ...) are listed
//! with `pointer_args = true` and are **not** user-callable: user code uses
//! the safe `sandblaster::arch::{aarch64,x86_64}` helpers ([`HELPERS`]), which
//! codegen emits as trusted glue (`#[target_feature] #[inline] fn` with an
//! unaligned load inside, §9.2).
//!
//! The formal models (core-text `DefKind::Intrinsic` globals) live in
//! `sandblaster/front/targets/` (owned by the targets work); phase 2
//! links [`IntrinsicId`]s to them by [`IntrinsicInfo::name`].

use std::sync::OnceLock;

use crate::hir::{Ty, UintTy};
use crate::target::Arch;

/// Hardware vector types (§9.2 vector representation).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum VecTy {
    /// NEON `uint8x16_t` = `Array(U8, 16)`.
    Uint8x16,
    /// NEON `uint8x8_t` = `Array(U8, 8)`.
    Uint8x8,
    /// NEON `uint16x8_t`.
    Uint16x8,
    /// NEON `uint32x4_t` = `Array(U32, 4)`.
    Uint32x4,
    /// NEON `uint32x2_t`.
    Uint32x2,
    /// NEON `uint64x2_t`.
    Uint64x2,
    /// x86 `__m128i` = `Array(U8, 16)` little-endian.
    M128i,
    /// x86 `__m256i` = `Array(U8, 32)`.
    M256i,
    /// x86 `__m512i` = `Array(U8, 64)`.
    M512i,
}

impl VecTy {
    pub const ALL: [VecTy; 9] = [VecTy::Uint8x16, VecTy::Uint8x8, VecTy::Uint16x8, VecTy::Uint32x4, VecTy::Uint32x2, VecTy::Uint64x2, VecTy::M128i, VecTy::M256i, VecTy::M512i];

    /// The stdarch type name.
    pub fn rust_name(self) -> &'static str {
        match self {
            VecTy::Uint8x16 => "uint8x16_t",
            VecTy::Uint8x8 => "uint8x8_t",
            VecTy::Uint16x8 => "uint16x8_t",
            VecTy::Uint32x4 => "uint32x4_t",
            VecTy::Uint32x2 => "uint32x2_t",
            VecTy::Uint64x2 => "uint64x2_t",
            VecTy::M128i => "__m128i",
            VecTy::M256i => "__m256i",
            VecTy::M512i => "__m512i",
        }
    }
    pub fn arch(self) -> Arch {
        match self {
            VecTy::M128i | VecTy::M256i | VecTy::M512i => Arch::X86_64,
            _ => Arch::Aarch64,
        }
    }
    /// Lane type and count of the canonical model representation.
    pub fn lanes(self) -> (UintTy, u64) {
        match self {
            VecTy::Uint8x16 => (UintTy::U8, 16),
            VecTy::Uint8x8 => (UintTy::U8, 8),
            VecTy::Uint16x8 => (UintTy::U16, 8),
            VecTy::Uint32x4 => (UintTy::U32, 4),
            VecTy::Uint32x2 => (UintTy::U32, 2),
            VecTy::Uint64x2 => (UintTy::U64, 2),
            VecTy::M128i => (UintTy::U8, 16),
            VecTy::M256i => (UintTy::U8, 32),
            VecTy::M512i => (UintTy::U8, 64),
        }
    }
    /// Absolute path used by the canonical printer.
    pub fn path(self) -> String {
        format!("::core::arch::{}::{}", self.arch().name(), self.rust_name())
    }
    pub fn from_name(arch: &Arch, name: &str) -> Option<VecTy> {
        VecTy::ALL.into_iter().find(|v| v.rust_name() == name && &v.arch() == arch)
    }
}

/// Index into [`table`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct IntrinsicId(pub u32);

/// A literal `i32` const-generic immediate and its accepted range.
#[derive(Clone, Debug)]
pub struct Imm {
    pub name: &'static str,
    pub lo: i64,
    pub hi: i64,
}

/// One intrinsic.
#[derive(Clone, Debug)]
pub struct IntrinsicInfo {
    pub id: IntrinsicId,
    pub name: &'static str,
    pub arch: Arch,
    /// Every feature listed must be in the caller's feature set.
    pub features: &'static [&'static str],
    pub params: Vec<Ty>,
    pub imms: Vec<Imm>,
    pub ret: Ty,
    /// Takes raw pointers (not callable from user code; use a helper).
    pub pointer_args: bool,
}

impl IntrinsicInfo {
    /// Absolute path (`::core::arch::aarch64::vaddq_u32`).
    pub fn path(&self) -> String {
        format!("::core::arch::{}::{}", self.arch.name(), self.name)
    }
}

fn v(t: VecTy) -> Ty {
    Ty::Vector(t)
}

/// The full intrinsic table (built once).
pub fn table() -> &'static [IntrinsicInfo] {
    static TABLE: OnceLock<Vec<IntrinsicInfo>> = OnceLock::new();
    TABLE.get_or_init(build_table)
}

pub fn get(id: IntrinsicId) -> &'static IntrinsicInfo {
    &table()[id.0 as usize]
}

/// Looks an intrinsic up by architecture and name.
pub fn lookup(arch: &Arch, name: &str) -> Option<&'static IntrinsicInfo> {
    table().iter().find(|i| &i.arch == arch && i.name == name)
}

fn build_table() -> Vec<IntrinsicInfo> {
    use VecTy::*;
    let mut t: Vec<IntrinsicInfo> = Vec::new();
    let mut add = |name: &'static str, arch: Arch, features: &'static [&'static str], params: Vec<Ty>, imms: &[(&'static str, i64, i64)], ret: Ty, pointer_args: bool| {
        let id = IntrinsicId(t.len() as u32);
        t.push(IntrinsicInfo { id, name, arch, features, params, imms: imms.iter().map(|&(name, lo, hi)| Imm { name, lo, hi }).collect(), ret, pointer_args });
    };
    let a = || Arch::Aarch64;
    let x = || Arch::X86_64;
    const NEON: &[&str] = &["neon"];
    const SHA2: &[&str] = &["sha2"];
    const AES: &[&str] = &["aes"];
    let u32t = Ty::Uint(UintTy::U32);
    let u8t = Ty::Uint(UintTy::U8);
    let u64t = Ty::Uint(UintTy::U64);

    // ---- aarch64: loads/stores (pointer args; use the helpers) ----
    add("vld1q_u8", a(), NEON, vec![], &[], v(Uint8x16), true);
    add("vld1q_u32", a(), NEON, vec![], &[], v(Uint32x4), true);
    add("vld1q_u64", a(), NEON, vec![], &[], v(Uint64x2), true);
    add("vld1_u8", a(), NEON, vec![], &[], v(Uint8x8), true);
    add("vst1q_u8", a(), NEON, vec![], &[], Ty::unit(), true);
    add("vst1q_u32", a(), NEON, vec![], &[], Ty::unit(), true);
    add("vst1q_u64", a(), NEON, vec![], &[], Ty::unit(), true);
    // ---- aarch64: permutes / reinterprets ----
    add("vrev32q_u8", a(), NEON, vec![v(Uint8x16)], &[], v(Uint8x16), false);
    add("vrev64q_u8", a(), NEON, vec![v(Uint8x16)], &[], v(Uint8x16), false);
    add("vreinterpretq_u32_u8", a(), NEON, vec![v(Uint8x16)], &[], v(Uint32x4), false);
    add("vreinterpretq_u8_u32", a(), NEON, vec![v(Uint32x4)], &[], v(Uint8x16), false);
    add("vreinterpretq_u64_u8", a(), NEON, vec![v(Uint8x16)], &[], v(Uint64x2), false);
    add("vreinterpretq_u8_u64", a(), NEON, vec![v(Uint64x2)], &[], v(Uint8x16), false);
    add("vreinterpretq_u32_u64", a(), NEON, vec![v(Uint64x2)], &[], v(Uint32x4), false);
    add("vreinterpretq_u64_u32", a(), NEON, vec![v(Uint32x4)], &[], v(Uint64x2), false);
    add("vqtbl1q_u8", a(), NEON, vec![v(Uint8x16), v(Uint8x16)], &[], v(Uint8x16), false);
    add("vcombine_u8", a(), NEON, vec![v(Uint8x8), v(Uint8x8)], &[], v(Uint8x16), false);
    add("vget_low_u8", a(), NEON, vec![v(Uint8x16)], &[], v(Uint8x8), false);
    add("vget_high_u8", a(), NEON, vec![v(Uint8x16)], &[], v(Uint8x8), false);
    add("vextq_u8", a(), NEON, vec![v(Uint8x16), v(Uint8x16)], &[("N", 0, 15)], v(Uint8x16), false);
    add("vextq_u32", a(), NEON, vec![v(Uint32x4), v(Uint32x4)], &[("N", 0, 3)], v(Uint32x4), false);
    add("vextq_u64", a(), NEON, vec![v(Uint64x2), v(Uint64x2)], &[("N", 0, 1)], v(Uint64x2), false);
    // ---- aarch64: lane-wise arithmetic / logic ----
    for (name, t) in [("vaddq_u8", Uint8x16), ("vaddq_u32", Uint32x4), ("vaddq_u64", Uint64x2), ("vsubq_u32", Uint32x4)] {
        add(name, a(), NEON, vec![v(t), v(t)], &[], v(t), false);
    }
    for (name, t) in [
        ("veorq_u8", Uint8x16),
        ("veorq_u32", Uint32x4),
        ("veorq_u64", Uint64x2),
        ("vandq_u8", Uint8x16),
        ("vandq_u32", Uint32x4),
        ("vandq_u64", Uint64x2),
        ("vorrq_u8", Uint8x16),
        ("vorrq_u32", Uint32x4),
        ("vorrq_u64", Uint64x2),
        ("vbicq_u32", Uint32x4),
    ] {
        add(name, a(), NEON, vec![v(t), v(t)], &[], v(t), false);
    }
    add("vmvnq_u8", a(), NEON, vec![v(Uint8x16)], &[], v(Uint8x16), false);
    add("vmvnq_u32", a(), NEON, vec![v(Uint32x4)], &[], v(Uint32x4), false);
    add("vbslq_u32", a(), NEON, vec![v(Uint32x4), v(Uint32x4), v(Uint32x4)], &[], v(Uint32x4), false);
    add("vshlq_n_u8", a(), NEON, vec![v(Uint8x16)], &[("N", 0, 7)], v(Uint8x16), false);
    add("vshrq_n_u8", a(), NEON, vec![v(Uint8x16)], &[("N", 1, 8)], v(Uint8x16), false);
    add("vshlq_n_u32", a(), NEON, vec![v(Uint32x4)], &[("N", 0, 31)], v(Uint32x4), false);
    add("vshrq_n_u32", a(), NEON, vec![v(Uint32x4)], &[("N", 1, 32)], v(Uint32x4), false);
    add("vshlq_n_u64", a(), NEON, vec![v(Uint64x2)], &[("N", 0, 63)], v(Uint64x2), false);
    add("vshrq_n_u64", a(), NEON, vec![v(Uint64x2)], &[("N", 1, 64)], v(Uint64x2), false);
    add("vdupq_n_u8", a(), NEON, vec![u8t.clone()], &[], v(Uint8x16), false);
    add("vdupq_n_u32", a(), NEON, vec![u32t.clone()], &[], v(Uint32x4), false);
    add("vdupq_n_u64", a(), NEON, vec![u64t.clone()], &[], v(Uint64x2), false);
    add("vgetq_lane_u8", a(), NEON, vec![v(Uint8x16)], &[("IMM5", 0, 15)], u8t.clone(), false);
    add("vgetq_lane_u32", a(), NEON, vec![v(Uint32x4)], &[("IMM5", 0, 3)], u32t.clone(), false);
    add("vgetq_lane_u64", a(), NEON, vec![v(Uint64x2)], &[("IMM5", 0, 1)], u64t.clone(), false);
    add("vsetq_lane_u8", a(), NEON, vec![u8t.clone(), v(Uint8x16)], &[("LANE", 0, 15)], v(Uint8x16), false);
    add("vsetq_lane_u32", a(), NEON, vec![u32t.clone(), v(Uint32x4)], &[("LANE", 0, 3)], v(Uint32x4), false);
    add("vsetq_lane_u64", a(), NEON, vec![u64t.clone(), v(Uint64x2)], &[("LANE", 0, 1)], v(Uint64x2), false);
    // ---- aarch64: plan O10 byte/halfword/doubleword lane operations ----
    for name in ["vcltq_u8", "vcgeq_u8", "vceqq_u8"] {
        add(name, a(), NEON, vec![v(Uint8x16), v(Uint8x16)], &[], v(Uint8x16), false);
    }
    add("vcntq_u8", a(), NEON, vec![v(Uint8x16)], &[], v(Uint8x16), false);
    add("vaddvq_u8", a(), NEON, vec![v(Uint8x16)], &[], u8t.clone(), false);
    add("vmaxvq_u8", a(), NEON, vec![v(Uint8x16)], &[], u8t.clone(), false);
    add("vreinterpretq_u16_u8", a(), NEON, vec![v(Uint8x16)], &[], v(Uint16x8), false);
    add("vshrn_n_u16", a(), NEON, vec![v(Uint16x8)], &[("N", 1, 8)], v(Uint8x8), false);
    add("vshrn_n_u64", a(), NEON, vec![v(Uint64x2)], &[("N", 1, 32)], v(Uint32x2), false);
    add("vmovn_u64", a(), NEON, vec![v(Uint64x2)], &[], v(Uint32x2), false);
    add("vsraq_n_u64", a(), NEON, vec![v(Uint64x2), v(Uint64x2)], &[("N", 1, 64)], v(Uint64x2), false);
    add("vbslq_u64", a(), NEON, vec![v(Uint64x2), v(Uint64x2), v(Uint64x2)], &[], v(Uint64x2), false);
    add("vmull_u32", a(), NEON, vec![v(Uint32x2), v(Uint32x2)], &[], v(Uint64x2), false);
    add("vmlal_u32", a(), NEON, vec![v(Uint64x2), v(Uint32x2), v(Uint32x2)], &[], v(Uint64x2), false);
    // ---- aarch64: FEAT_SHA3 / FEAT_SHA512 (rustc feature `sha3`) ----
    const SHA3: &[&str] = &["sha3"];
    add("veor3q_u8", a(), SHA3, vec![v(Uint8x16), v(Uint8x16), v(Uint8x16)], &[], v(Uint8x16), false);
    add("vbcaxq_u8", a(), SHA3, vec![v(Uint8x16), v(Uint8x16), v(Uint8x16)], &[], v(Uint8x16), false);
    add("vrax1q_u64", a(), SHA3, vec![v(Uint64x2), v(Uint64x2)], &[], v(Uint64x2), false);
    add("vxarq_u64", a(), SHA3, vec![v(Uint64x2), v(Uint64x2)], &[("IMM6", 0, 63)], v(Uint64x2), false);
    for name in ["vsha512hq_u64", "vsha512h2q_u64", "vsha512su1q_u64"] {
        add(name, a(), SHA3, vec![v(Uint64x2), v(Uint64x2), v(Uint64x2)], &[], v(Uint64x2), false);
    }
    add("vsha512su0q_u64", a(), SHA3, vec![v(Uint64x2), v(Uint64x2)], &[], v(Uint64x2), false);
    // ---- aarch64: SHA2 / AES ----
    add("vsha256hq_u32", a(), SHA2, vec![v(Uint32x4), v(Uint32x4), v(Uint32x4)], &[], v(Uint32x4), false);
    add("vsha256h2q_u32", a(), SHA2, vec![v(Uint32x4), v(Uint32x4), v(Uint32x4)], &[], v(Uint32x4), false);
    add("vsha256su0q_u32", a(), SHA2, vec![v(Uint32x4), v(Uint32x4)], &[], v(Uint32x4), false);
    add("vsha256su1q_u32", a(), SHA2, vec![v(Uint32x4), v(Uint32x4), v(Uint32x4)], &[], v(Uint32x4), false);
    add("vaeseq_u8", a(), AES, vec![v(Uint8x16), v(Uint8x16)], &[], v(Uint8x16), false);
    add("vaesmcq_u8", a(), AES, vec![v(Uint8x16)], &[], v(Uint8x16), false);

    // ---- x86_64: loads/stores (pointer args; use the helpers) ----
    add("_mm_loadu_si128", x(), &["sse2"], vec![], &[], v(M128i), true);
    add("_mm_storeu_si128", x(), &["sse2"], vec![], &[], Ty::unit(), true);
    add("_mm256_loadu_si256", x(), &["avx"], vec![], &[], v(M256i), true);
    add("_mm256_storeu_si256", x(), &["avx"], vec![], &[], Ty::unit(), true);
    add("_mm512_loadu_si512", x(), &["avx512f"], vec![], &[], v(M512i), true);
    add("_mm512_storeu_si512", x(), &["avx512f"], vec![], &[], Ty::unit(), true);
    // ---- x86_64: SSE2..SSE4.1 ----
    let m = || v(M128i);
    add("_mm_setzero_si128", x(), &["sse2"], vec![], &[], m(), false);
    for name in ["_mm_add_epi32", "_mm_add_epi64", "_mm_sub_epi32", "_mm_xor_si128", "_mm_and_si128", "_mm_or_si128", "_mm_andnot_si128", "_mm_unpacklo_epi32", "_mm_unpackhi_epi32", "_mm_unpacklo_epi64", "_mm_unpackhi_epi64"] {
        add(name, x(), &["sse2"], vec![m(), m()], &[], m(), false);
    }
    add("_mm_shuffle_epi32", x(), &["sse2"], vec![m()], &[("IMM8", 0, 255)], m(), false);
    for name in ["_mm_slli_epi32", "_mm_srli_epi32", "_mm_slli_epi64", "_mm_srli_epi64", "_mm_slli_si128", "_mm_srli_si128"] {
        add(name, x(), &["sse2"], vec![m()], &[("IMM8", 0, 255)], m(), false);
    }
    add("_mm_shuffle_epi8", x(), &["ssse3"], vec![m(), m()], &[], m(), false);
    add("_mm_alignr_epi8", x(), &["ssse3"], vec![m(), m()], &[("IMM8", 0, 255)], m(), false);
    add("_mm_blend_epi16", x(), &["sse4.1"], vec![m(), m()], &[("IMM8", 0, 255)], m(), false);
    // ---- x86_64: SHA-NI / AES-NI ----
    add("_mm_sha256rnds2_epu32", x(), &["sha"], vec![m(), m(), m()], &[], m(), false);
    add("_mm_sha256msg1_epu32", x(), &["sha"], vec![m(), m()], &[], m(), false);
    add("_mm_sha256msg2_epu32", x(), &["sha"], vec![m(), m()], &[], m(), false);
    add("_mm_aesenc_si128", x(), &["aes"], vec![m(), m()], &[], m(), false);
    // ---- x86_64: AVX2 ----
    let y = || v(M256i);
    add("_mm256_setzero_si256", x(), &["avx"], vec![], &[], y(), false);
    for name in ["_mm256_add_epi32", "_mm256_xor_si256", "_mm256_and_si256", "_mm256_or_si256", "_mm256_andnot_si256", "_mm256_shuffle_epi8"] {
        add(name, x(), &["avx2"], vec![y(), y()], &[], y(), false);
    }
    for name in ["_mm256_slli_epi32", "_mm256_srli_epi32"] {
        add(name, x(), &["avx2"], vec![y()], &[("IMM8", 0, 255)], y(), false);
    }
    // ---- x86_64: AVX-512 ----
    let z = || v(M512i);
    for name in ["_mm512_add_epi32", "_mm512_xor_si512", "_mm512_and_si512", "_mm512_or_si512"] {
        add(name, x(), &["avx512f"], vec![z(), z()], &[], z(), false);
    }
    add("_mm512_ternarylogic_epi32", x(), &["avx512f"], vec![z(), z(), z()], &[("IMM8", 0, 255)], z(), false);
    add("_mm512_ror_epi32", x(), &["avx512f"], vec![z()], &[("IMM8", 0, 255)], z(), false);
    add("_mm512_rol_epi32", x(), &["avx512f"], vec![z()], &[("IMM8", 0, 255)], z(), false);
    // plan O10 (lane kernels): shifts by an immediate (stdarch `const IMM8: u32`)
    for name in ["_mm512_slli_epi32", "_mm512_srli_epi32"] {
        add(name, x(), &["avx512f"], vec![z()], &[("IMM8", 0, 255)], z(), false);
    }
    t
}

/// Type aliases exported by `core::arch::<arch>` that the subset accepts
/// (AVX-512 masks are plain unsigned integers, §9.2).
pub fn arch_type_alias(arch: &Arch, name: &str) -> Option<Ty> {
    match (arch, name) {
        (Arch::X86_64, "__mmask8") => Some(Ty::Uint(UintTy::U8)),
        (Arch::X86_64, "__mmask16") => Some(Ty::Uint(UintTy::U16)),
        _ => None,
    }
}

/// Index into [`HELPERS`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct HelperId(pub u32);

/// A safe load/store helper of `sandblaster::arch::<arch>` (trusted glue).
#[derive(Clone, Debug)]
pub struct HelperInfo {
    pub name: &'static str,
    pub arch: Arch,
    /// The `#[target_feature(enable = ..)]` of the generated helper; callers
    /// need these features.
    pub features: &'static [&'static str],
    pub params: Vec<Ty>,
    pub ret: Ty,
    /// Rust source of the generated helper function (parameter `a` or `v`).
    pub template: &'static str,
}

/// The helper table.
pub fn helpers() -> &'static [HelperInfo] {
    static H: OnceLock<Vec<HelperInfo>> = OnceLock::new();
    H.get_or_init(build_helpers)
}

pub fn helper(id: HelperId) -> &'static HelperInfo {
    &helpers()[id.0 as usize]
}

/// The Rust source the printer emits for helper `id`: its
/// [`HelperInfo::template`], or, in test builds only, a replacement a
/// must-reject test installed on this thread
/// (`opt::hooks::with_helper_template`; R26: a changed template must rename
/// the lane kernels that call the helper).
pub fn helper_template(id: HelperId) -> &'static str {
    #[cfg(any(test, feature = "opt-test-hooks"))]
    if let Some(t) = TEMPLATE_OVERRIDE.with(|o| o.borrow().get(&id).copied()) {
        return t;
    }
    helper(id).template
}

#[cfg(any(test, feature = "opt-test-hooks"))]
thread_local! {
    /// Test-only template replacements ([`helper_template`]).
    pub(crate) static TEMPLATE_OVERRIDE: std::cell::RefCell<std::collections::HashMap<HelperId, &'static str>> = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Looks a helper up by architecture and name.
pub fn lookup_helper(arch: &Arch, name: &str) -> Option<HelperId> {
    helpers().iter().position(|h| &h.arch == arch && h.name == name).map(|i| HelperId(i as u32))
}

fn build_helpers() -> Vec<HelperInfo> {
    use VecTy::*;
    let arr = |t: UintTy, n: u64| Ty::array(Ty::Uint(t), n);
    let r = |t: Ty| Ty::reference(t);
    vec![
        HelperInfo { name: "load_u8x16", arch: Arch::Aarch64, features: &["neon"], params: vec![r(arr(UintTy::U8, 16))], ret: v(Uint8x16), template: "unsafe { ::core::arch::aarch64::vld1q_u8(a.as_ptr()) }" },
        HelperInfo { name: "load_u32x4", arch: Arch::Aarch64, features: &["neon"], params: vec![r(arr(UintTy::U32, 4))], ret: v(Uint32x4), template: "unsafe { ::core::arch::aarch64::vld1q_u32(a.as_ptr()) }" },
        HelperInfo { name: "load_u64x2", arch: Arch::Aarch64, features: &["neon"], params: vec![r(arr(UintTy::U64, 2))], ret: v(Uint64x2), template: "unsafe { ::core::arch::aarch64::vld1q_u64(a.as_ptr()) }" },
        HelperInfo { name: "load_u8x8", arch: Arch::Aarch64, features: &["neon"], params: vec![r(arr(UintTy::U8, 8))], ret: v(Uint8x8), template: "unsafe { ::core::arch::aarch64::vld1_u8(a.as_ptr()) }" },
        HelperInfo { name: "store_u8x16", arch: Arch::Aarch64, features: &["neon"], params: vec![v(Uint8x16)], ret: arr(UintTy::U8, 16), template: "let mut out = [0u8; 16]; unsafe { ::core::arch::aarch64::vst1q_u8(out.as_mut_ptr(), a) }; out" },
        HelperInfo { name: "store_u32x4", arch: Arch::Aarch64, features: &["neon"], params: vec![v(Uint32x4)], ret: arr(UintTy::U32, 4), template: "let mut out = [0u32; 4]; unsafe { ::core::arch::aarch64::vst1q_u32(out.as_mut_ptr(), a) }; out" },
        HelperInfo { name: "store_u64x2", arch: Arch::Aarch64, features: &["neon"], params: vec![v(Uint64x2)], ret: arr(UintTy::U64, 2), template: "let mut out = [0u64; 2]; unsafe { ::core::arch::aarch64::vst1q_u64(out.as_mut_ptr(), a) }; out" },
        HelperInfo { name: "load_u8x16", arch: Arch::X86_64, features: &["sse2"], params: vec![r(arr(UintTy::U8, 16))], ret: v(M128i), template: "unsafe { ::core::arch::x86_64::_mm_loadu_si128(a.as_ptr().cast()) }" },
        HelperInfo { name: "load_u32x4", arch: Arch::X86_64, features: &["sse2"], params: vec![r(arr(UintTy::U32, 4))], ret: v(M128i), template: "unsafe { ::core::arch::x86_64::_mm_loadu_si128(a.as_ptr().cast()) }" },
        HelperInfo { name: "m128i_from_u32x4", arch: Arch::X86_64, features: &["sse2"], params: vec![arr(UintTy::U32, 4)], ret: v(M128i), template: "unsafe { ::core::arch::x86_64::_mm_loadu_si128(a.as_ptr().cast()) }" },
        HelperInfo { name: "store_u8x16", arch: Arch::X86_64, features: &["sse2"], params: vec![v(M128i)], ret: arr(UintTy::U8, 16), template: "let mut out = [0u8; 16]; unsafe { ::core::arch::x86_64::_mm_storeu_si128(out.as_mut_ptr().cast(), a) }; out" },
        HelperInfo { name: "store_u32x4", arch: Arch::X86_64, features: &["sse2"], params: vec![v(M128i)], ret: arr(UintTy::U32, 4), template: "let mut out = [0u32; 4]; unsafe { ::core::arch::x86_64::_mm_storeu_si128(out.as_mut_ptr().cast(), a) }; out" },
        HelperInfo { name: "load_u8x32", arch: Arch::X86_64, features: &["avx"], params: vec![r(arr(UintTy::U8, 32))], ret: v(M256i), template: "unsafe { ::core::arch::x86_64::_mm256_loadu_si256(a.as_ptr().cast()) }" },
        HelperInfo { name: "load_u32x8", arch: Arch::X86_64, features: &["avx"], params: vec![r(arr(UintTy::U32, 8))], ret: v(M256i), template: "unsafe { ::core::arch::x86_64::_mm256_loadu_si256(a.as_ptr().cast()) }" },
        HelperInfo { name: "store_u8x32", arch: Arch::X86_64, features: &["avx"], params: vec![v(M256i)], ret: arr(UintTy::U8, 32), template: "let mut out = [0u8; 32]; unsafe { ::core::arch::x86_64::_mm256_storeu_si256(out.as_mut_ptr().cast(), a) }; out" },
        HelperInfo { name: "store_u32x8", arch: Arch::X86_64, features: &["avx"], params: vec![v(M256i)], ret: arr(UintTy::U32, 8), template: "let mut out = [0u32; 8]; unsafe { ::core::arch::x86_64::_mm256_storeu_si256(out.as_mut_ptr().cast(), a) }; out" },
        // plan O10: the AVX-512 lane kernels' pack and unpack
        HelperInfo { name: "load_u8x64", arch: Arch::X86_64, features: &["avx512f"], params: vec![r(arr(UintTy::U8, 64))], ret: v(M512i), template: "unsafe { ::core::arch::x86_64::_mm512_loadu_si512(a.as_ptr().cast()) }" },
        HelperInfo { name: "load_u32x16", arch: Arch::X86_64, features: &["avx512f"], params: vec![r(arr(UintTy::U32, 16))], ret: v(M512i), template: "unsafe { ::core::arch::x86_64::_mm512_loadu_si512(a.as_ptr().cast()) }" },
        HelperInfo { name: "store_u32x16", arch: Arch::X86_64, features: &["avx512f"], params: vec![v(M512i)], ret: arr(UintTy::U32, 16), template: "let mut out = [0u32; 16]; unsafe { ::core::arch::x86_64::_mm512_storeu_si512(out.as_mut_ptr().cast(), a) }; out" },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything DESIGN.md §9.2 lists as initial coverage is in the table.
    #[test]
    fn covers_design_initial_list() {
        let a = Arch::Aarch64;
        for n in [
            "vld1q_u8", "vld1q_u32", "vld1_u8", "vst1q_u8", "vst1q_u32", "vrev32q_u8", "vreinterpretq_u32_u8", "vreinterpretq_u8_u32", "vaddq_u32", "veorq_u32", "veorq_u8", "vandq_u32", "vorrq_u32", "vshlq_n_u32", "vshrq_n_u32", "vextq_u32", "vextq_u8", "vdupq_n_u32", "vgetq_lane_u32", "vsetq_lane_u32", "vsha256hq_u32", "vsha256h2q_u32", "vsha256su0q_u32", "vsha256su1q_u32",
        ] {
            assert!(lookup(&a, n).is_some(), "{n}");
        }
        let x = Arch::X86_64;
        for n in ["_mm_loadu_si128", "_mm_storeu_si128", "_mm_shuffle_epi8", "_mm_shuffle_epi32", "_mm_alignr_epi8", "_mm_blend_epi16", "_mm_add_epi32", "_mm_sha256rnds2_epu32", "_mm_sha256msg1_epu32", "_mm_sha256msg2_epu32", "_mm256_add_epi32", "_mm512_ternarylogic_epi32"] {
            assert!(lookup(&x, n).is_some(), "{n}");
        }
        assert!(lookup(&a, "vsha256hq_u32").unwrap().features == ["sha2"]);
        assert!(lookup(&x, "_mm_sha256rnds2_epu32").unwrap().features == ["sha"]);
    }
}
