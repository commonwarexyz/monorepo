//! Native implementation of the Armv9-A SVE2 instruction profile.

use super::neon::NativeNeon;
use crate::{ArmV9, Neon, Operation, Simd};
use core::arch::asm;

/// Native Armv9 execution token with 16 byte, four u32, and two u64 lanes.
///
/// This profile includes NEON and SHA2 with fixed 128-bit logical vectors.
/// It does not expose scalable SVE vectors.
///
/// Construction checks NEON, SHA2, SVE, and SVE2. Only the low 128 bits are
/// modeled, independently of the full SVE width. Every SVE vector length is at
/// least 128 bits, so the fixed lane counts hold on any thread.
#[derive(Clone, Copy, Debug)]
pub struct NativeArmV9(NativeNeon);

impl NativeArmV9 {
    /// Returns a token if NEON, SHA2, SVE, and SVE2 are available.
    ///
    /// With `std`, detects features at runtime. Without `std`, requires them
    /// to be enabled at compile time.
    #[inline]
    pub fn new() -> Option<Self> {
        let neon = NativeNeon::new()?;
        #[cfg(feature = "std")]
        let supported = std::arch::is_aarch64_feature_detected!("sve")
            && std::arch::is_aarch64_feature_detected!("sve2");
        #[cfg(not(feature = "std"))]
        let supported = cfg!(target_feature = "sve") && cfg!(target_feature = "sve2");
        supported.then_some(Self(neon))
    }

    #[inline]
    #[target_feature(enable = "neon,sha2,sve,sve2")]
    unsafe fn execute_arm_v9<O: Operation<Self>>(self, operation: O) -> O::Output {
        operation.arm_v9(self)
    }

    /// Applies the destructive SVE2 bitwise instruction `ENCODING` with `dn` in Zdn, `m` in
    /// Zm, and `k` in Zk, and returns the new Zdn.
    #[inline]
    fn sve2_bitwise3<const ENCODING: u32>(
        self,
        mut dn: <Self as Simd>::U64,
        m: <Self as Simd>::U64,
        k: <Self as Simd>::U64,
    ) -> <Self as Simd>::U64 {
        const { assert!(ENCODING == EOR3_ENCODING || ENCODING == BCAX_ENCODING) };
        // SAFETY: Construction established NEON, SVE, and SVE2. Every SVE vector
        // length is at least 128 bits. Vn aliases Zn's low 128 bits, and EOR3
        // and BCAX are bitwise, so arbitrary higher source bits cannot affect
        // the modeled lanes. Only the declared destination register is written,
        // and both other source registers are preserved. Destination bits above
        // 128 may change, and no Rust value of this type observes them. Neither
        // instruction accesses memory, the stack, or flags.
        unsafe {
            asm!(
                ".irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
                ".ifc {dn:v},v\\n",
                ".set .Lsve2_dn, \\n",
                ".endif",
                ".ifc {m:v},v\\n",
                ".set .Lsve2_m, \\n",
                ".endif",
                ".ifc {k:v},v\\n",
                ".set .Lsve2_k, \\n",
                ".endif",
                ".endr",
                ".inst {encoding} + (.Lsve2_m << 16) + (.Lsve2_k << 5) + .Lsve2_dn",
                dn = inout(vreg) dn,
                m = in(vreg) m,
                k = in(vreg) k,
                encoding = const ENCODING,
                options(pure, nomem, nostack, preserves_flags),
            );
        }
        dn
    }
}

const _: () = crate::core::assert_lane_relation::<NativeArmV9>();

impl Simd for NativeArmV9 {
    type U32x4 = <NativeNeon as Simd>::U32x4;

    #[inline]
    fn u32x4_load(self, input: &[u32]) -> Self::U32x4 {
        self.0.u32x4_load(input)
    }

    #[inline]
    fn u32x4_store(self, value: Self::U32x4, output: &mut [u32]) {
        self.0.u32x4_store(value, output)
    }

    #[inline]
    fn u32x4_add(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        self.0.u32x4_add(a, b)
    }

    #[inline]
    fn u32x4_shuffle<const MASK: i32>(self, value: Self::U32x4) -> Self::U32x4 {
        self.0.u32x4_shuffle::<MASK>(value)
    }

    #[inline]
    fn u32x4_load_be(self, input: &[u8]) -> Self::U32x4 {
        self.0.u32x4_load_be(input)
    }

    #[inline]
    fn u32x4_load_be2(self, input: &[u8]) -> Self::U32x4 {
        self.0.u32x4_load_be2(input)
    }

    #[inline]
    fn u32x4_store_be(self, value: Self::U32x4, output: &mut [u8]) {
        self.0.u32x4_store_be(value, output)
    }

    #[inline]
    fn u32x4_align<const N: i32>(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        self.0.u32x4_align::<N>(a, b)
    }

    #[inline]
    fn u32x4_blend<const MASK: i32>(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        self.0.u32x4_blend::<MASK>(a, b)
    }

    type U8 = <NativeNeon as Simd>::U8;
    const U8_LANES: usize = 16;
    type U32 = <NativeNeon as Simd>::U32;
    const U32_LANES: usize = 4;
    type U64 = <NativeNeon as Simd>::U64;
    const U64_LANES: usize = 2;

    #[inline]
    fn u8_load(self, input: &[u8]) -> Self::U8 {
        self.0.u8_load(input)
    }

    #[inline]
    fn u8_store(self, value: Self::U8, output: &mut [u8]) {
        self.0.u8_store(value, output)
    }

    #[inline]
    fn u8_splat(self, value: u8) -> Self::U8 {
        self.0.u8_splat(value)
    }

    #[inline]
    fn u8_xor(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_xor(a, b)
    }

    #[inline]
    fn u8_load_partial(self, input: &[u8]) -> Self::U8 {
        self.0.u8_load_partial(input)
    }

    #[inline]
    fn u8_store_partial(self, value: Self::U8, output: &mut [u8]) {
        self.0.u8_store_partial(value, output)
    }

    #[inline]
    fn u8_and(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_and(a, b)
    }

    type U8Table = <NativeNeon as Simd>::U8Table;

    #[inline]
    fn u8_table_load(self, table: &[u8; 16]) -> Self::U8Table {
        self.0.u8_table_load(table)
    }

    #[inline]
    fn u8_table_lookup(self, table: Self::U8Table, indices: Self::U8) -> Self::U8 {
        self.0.u8_table_lookup(table, indices)
    }

    #[inline]
    fn u8_or(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_or(a, b)
    }

    #[inline]
    fn u8_add(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_add(a, b)
    }

    #[inline]
    fn u8_sub(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_sub(a, b)
    }

    #[inline]
    fn u8_add_saturating(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_add_saturating(a, b)
    }

    #[inline]
    fn u8_sub_saturating(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_sub_saturating(a, b)
    }

    #[inline]
    fn u8_min(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_min(a, b)
    }

    #[inline]
    fn u8_max(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_max(a, b)
    }

    #[inline]
    fn u8_eq(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_eq(a, b)
    }

    #[inline]
    fn u8_gt(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_gt(a, b)
    }

    #[inline]
    fn u8_movemask(self, value: Self::U8) -> u64 {
        self.0.u8_movemask(value)
    }

    #[inline]
    fn u8_any(self, value: Self::U8) -> bool {
        self.0.u8_any(value)
    }

    #[inline]
    fn u8_all(self, value: Self::U8) -> bool {
        self.0.u8_all(value)
    }

    #[inline]
    fn u8_zip_lo(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_zip_lo(a, b)
    }

    #[inline]
    fn u8_zip_hi(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_zip_hi(a, b)
    }

    #[inline]
    fn u8_unzip_even(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_unzip_even(a, b)
    }

    #[inline]
    fn u8_unzip_odd(self, a: Self::U8, b: Self::U8) -> Self::U8 {
        self.0.u8_unzip_odd(a, b)
    }

    #[inline]
    fn u8_shl<const N: u32>(self, value: Self::U8) -> Self::U8 {
        self.0.u8_shl::<N>(value)
    }

    #[inline]
    fn u8_shr<const N: u32>(self, value: Self::U8) -> Self::U8 {
        self.0.u8_shr::<N>(value)
    }

    #[inline]
    fn u8_xor_fold(self, value: Self::U8) -> u8 {
        self.0.u8_xor_fold(value)
    }

    #[inline]
    fn u32_load(self, input: &[u32]) -> Self::U32 {
        self.0.u32_load(input)
    }

    #[inline]
    fn u32_store(self, value: Self::U32, output: &mut [u32]) {
        self.0.u32_store(value, output)
    }

    #[inline]
    fn u32_splat(self, value: u32) -> Self::U32 {
        self.0.u32_splat(value)
    }

    #[inline]
    fn u32_xor(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        self.0.u32_xor(a, b)
    }

    #[inline]
    fn u32_add(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        self.0.u32_add(a, b)
    }

    #[inline]
    fn u32_rotate_right<const N: u32>(self, value: Self::U32) -> Self::U32 {
        self.0.u32_rotate_right::<N>(value)
    }

    #[inline]
    fn u32_sub(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        self.0.u32_sub(a, b)
    }

    #[inline]
    fn u32_and(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        self.0.u32_and(a, b)
    }

    #[inline]
    fn u32_or(self, a: Self::U32, b: Self::U32) -> Self::U32 {
        self.0.u32_or(a, b)
    }

    #[inline]
    fn u32_shl<const N: u32>(self, value: Self::U32) -> Self::U32 {
        self.0.u32_shl::<N>(value)
    }

    #[inline]
    fn u32_shr<const N: u32>(self, value: Self::U32) -> Self::U32 {
        self.0.u32_shr::<N>(value)
    }

    #[inline]
    fn u32_select(self, mask: Self::U32, a: Self::U32, b: Self::U32) -> Self::U32 {
        self.0.u32_select(mask, a, b)
    }

    #[inline]
    fn u32_permute(self, value: Self::U32, indices: Self::U32) -> Self::U32 {
        self.0.u32_permute(value, indices)
    }

    #[inline]
    fn u32_permute2(self, a: Self::U32, b: Self::U32, indices: Self::U32) -> Self::U32 {
        self.0.u32_permute2(a, b, indices)
    }

    #[inline]
    fn u64_load(self, input: &[u64]) -> Self::U64 {
        self.0.u64_load(input)
    }

    #[inline]
    fn u64_store(self, value: Self::U64, output: &mut [u64]) {
        self.0.u64_store(value, output)
    }

    #[inline]
    fn u64_splat(self, value: u64) -> Self::U64 {
        self.0.u64_splat(value)
    }

    #[inline]
    fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        self.0.u64_add(a, b)
    }

    #[inline]
    fn u64_shl<const N: u32>(self, value: Self::U64) -> Self::U64 {
        self.0.u64_shl::<N>(value)
    }

    #[inline]
    fn u64_shr<const N: u32>(self, value: Self::U64) -> Self::U64 {
        self.0.u64_shr::<N>(value)
    }

    #[inline]
    fn u64_and(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        self.0.u64_and(a, b)
    }

    #[inline]
    fn u64_or(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        self.0.u64_or(a, b)
    }

    #[inline]
    fn u64_sub(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        self.0.u64_sub(a, b)
    }

    #[inline]
    fn u64_xor(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        self.0.u64_xor(a, b)
    }

    #[inline]
    fn u64_rotate_left<const N: u32>(self, value: Self::U64) -> Self::U64 {
        self.0.u64_rotate_left::<N>(value)
    }

    #[inline]
    fn u64_rotate_right<const N: u32>(self, value: Self::U64) -> Self::U64 {
        self.0.u64_rotate_right::<N>(value)
    }

    #[inline]
    fn u64_andnot(self, a: Self::U64, b: Self::U64) -> Self::U64 {
        self.0.u64_andnot(a, b)
    }

    #[inline]
    fn u64_xor3(self, a: Self::U64, b: Self::U64, c: Self::U64) -> Self::U64 {
        self.sve2_bitwise3::<EOR3_ENCODING>(a, b, c)
    }

    #[inline]
    fn u64_select(self, mask: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64 {
        self.0.u64_select(mask, a, b)
    }

    #[inline]
    fn u64_extract<const N: usize>(self, value: Self::U64) -> u64 {
        self.0.u64_extract::<N>(value)
    }

    #[inline]
    fn u64_insert<const N: usize>(self, value: Self::U64, lane: u64) -> Self::U64 {
        self.0.u64_insert::<N>(value, lane)
    }

    #[inline]
    fn u8_as_u32(self, value: Self::U8) -> Self::U32 {
        self.0.u8_as_u32(value)
    }

    #[inline]
    fn u32_as_u8(self, value: Self::U32) -> Self::U8 {
        self.0.u32_as_u8(value)
    }

    #[inline]
    fn u8_as_u64(self, value: Self::U8) -> Self::U64 {
        self.0.u8_as_u64(value)
    }

    #[inline]
    fn u64_as_u8(self, value: Self::U64) -> Self::U8 {
        self.0.u64_as_u8(value)
    }

    #[inline]
    fn u32_as_u64(self, value: Self::U32) -> Self::U64 {
        self.0.u32_as_u64(value)
    }

    #[inline]
    fn u64_as_u32(self, value: Self::U64) -> Self::U32 {
        self.0.u64_as_u32(value)
    }

    #[inline]
    fn execute<O: Operation<Self>>(self, operation: O) -> O::Output {
        // SAFETY: Construction checked NEON, SHA2, SVE, and SVE2. Passing
        // this token preserves the Armv9 path for nested child operations.
        unsafe { self.execute_arm_v9(operation) }
    }
}

impl Neon for NativeArmV9 {
    #[inline]
    fn sha256_h(self, abcd: Self::U32x4, efgh: Self::U32x4, wk: Self::U32x4) -> Self::U32x4 {
        self.0.sha256_h(abcd, efgh, wk)
    }
    #[inline]
    fn sha256_h2(self, efgh: Self::U32x4, abcd: Self::U32x4, wk: Self::U32x4) -> Self::U32x4 {
        self.0.sha256_h2(efgh, abcd, wk)
    }
    #[inline]
    fn sha256_su0(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        self.0.sha256_su0(a, b)
    }
    #[inline]
    fn sha256_su1(self, a: Self::U32x4, b: Self::U32x4, c: Self::U32x4) -> Self::U32x4 {
        self.0.sha256_su1(a, b, c)
    }

    type U16 = <NativeNeon as Neon>::U16;
    type U32Half = <NativeNeon as Neon>::U32Half;

    #[inline]
    fn u8_table(self, table: Self::U8) -> Self::U8Table {
        self.0.u8_table(table)
    }

    #[inline]
    fn u8_clmul_lo(self, a: Self::U8, b: Self::U8) -> Self::U16 {
        self.0.u8_clmul_lo(a, b)
    }

    #[inline]
    fn u8_clmul_hi(self, a: Self::U8, b: Self::U8) -> Self::U16 {
        self.0.u8_clmul_hi(a, b)
    }

    #[inline]
    fn u16_xor(self, a: Self::U16, b: Self::U16) -> Self::U16 {
        self.0.u16_xor(a, b)
    }

    #[inline]
    fn u16_shl<const N: u32>(self, value: Self::U16) -> Self::U16 {
        self.0.u16_shl::<N>(value)
    }

    #[inline]
    fn u16_shr<const N: u32>(self, value: Self::U16) -> Self::U16 {
        self.0.u16_shr::<N>(value)
    }

    #[inline]
    fn u16_narrow_pair(self, low: Self::U16, high: Self::U16) -> Self::U8 {
        self.0.u16_narrow_pair(low, high)
    }

    #[inline]
    fn u64_narrow(self, value: Self::U64) -> Self::U32Half {
        self.0.u64_narrow(value)
    }

    #[inline]
    fn u32_half_splat(self, value: u32) -> Self::U32Half {
        self.0.u32_half_splat(value)
    }

    #[inline]
    fn u32_half_add(self, a: Self::U32Half, b: Self::U32Half) -> Self::U32Half {
        self.0.u32_half_add(a, b)
    }

    #[inline]
    fn u32_half_shl<const N: u32>(self, value: Self::U32Half) -> Self::U32Half {
        self.0.u32_half_shl::<N>(value)
    }

    #[inline]
    fn u32_widen_mul(self, a: Self::U32Half, b: Self::U32Half) -> Self::U64 {
        self.0.u32_widen_mul(a, b)
    }

    #[inline]
    fn u32_widen_madd(self, acc: Self::U64, a: Self::U32Half, b: Self::U32Half) -> Self::U64 {
        self.0.u32_widen_madd(acc, a, b)
    }
}

impl ArmV9 for NativeArmV9 {
    #[inline]
    fn u32_xor_rotate_right<const N: u32>(self, mut a: Self::U32, b: Self::U32) -> Self::U32 {
        assert!(N < 32);
        if N == 0 {
            return self.0.u32_xor(a, b);
        }
        // SAFETY: Construction established NEON, SVE, and SVE2. Every SVE vector
        // length is at least 128 bits. Vn aliases Zn's low 128 bits,
        // and XAR acts independently on 32-bit lanes, so arbitrary higher
        // source bits cannot affect the four modeled lanes. Only the declared
        // destination register is written, and the source register is preserved.
        // Destination bits above 128 may change, and no Rust value of this type
        // observes them. XAR does not access memory, the stack, or flags.
        unsafe {
            asm!(
                ".irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
                ".ifc {dn:v},v\\n",
                ".set .Lxar_dn, \\n",
                ".endif",
                ".ifc {m:v},v\\n",
                ".set .Lxar_m, \\n",
                ".endif",
                ".endr",
                ".inst {encoding} + (.Lxar_m << 5) + .Lxar_dn",
                dn = inout(vreg) a,
                m = in(vreg) b,
                encoding = const xar_encoding(N),
                options(pure, nomem, nostack, preserves_flags),
            );
        }
        a
    }

    #[inline]
    fn u64_xor_rotate_right<const N: u32>(self, mut a: Self::U64, b: Self::U64) -> Self::U64 {
        assert!(N < 64);
        if N == 0 {
            return self.0.u64_xor(a, b);
        }
        // SAFETY: Construction established NEON, SVE, and SVE2. Every SVE vector
        // length is at least 128 bits. Vn aliases Zn's low 128 bits,
        // and XAR acts independently on 64-bit lanes, so arbitrary higher
        // source bits cannot affect the two modeled lanes. Only the declared
        // destination register is written, and the source register is preserved.
        // Destination bits above 128 may change, and no Rust value of this type
        // observes them. XAR does not access memory, the stack, or flags.
        unsafe {
            asm!(
                ".irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
                ".ifc {dn:v},v\\n",
                ".set .Lxar_dn, \\n",
                ".endif",
                ".ifc {m:v},v\\n",
                ".set .Lxar_m, \\n",
                ".endif",
                ".endr",
                ".inst {encoding} + (.Lxar_m << 5) + .Lxar_dn",
                dn = inout(vreg) a,
                m = in(vreg) b,
                encoding = const xar64_encoding(N),
                options(pure, nomem, nostack, preserves_flags),
            );
        }
        a
    }

    #[inline]
    fn u64_bcax(self, a: Self::U64, b: Self::U64, c: Self::U64) -> Self::U64 {
        self.sve2_bitwise3::<BCAX_ENCODING>(a, b, c)
    }
}

/// Encodes XAR Zdn.S, Zdn.S, Zm.S with zero register fields.
const fn xar_encoding(rotation: u32) -> u32 {
    // Invalid rotations panic in the instruction method before reaching assembly.
    if rotation == 0 || rotation >= 32 {
        return 0;
    }
    // The element size and rotation share a field containing 64 - rotation.
    let field = 64 - rotation;
    0x0420_3400 | (((field >> 5) & 3) << 22) | (((field >> 3) & 3) << 19) | ((field & 7) << 16)
}

/// Encodes XAR Zdn.D, Zdn.D, Zm.D with zero register fields.
const fn xar64_encoding(rotation: u32) -> u32 {
    // Invalid rotations panic in the instruction method before reaching assembly.
    if rotation == 0 || rotation >= 64 {
        return 0;
    }
    // The element size and rotation share a field containing 128 - rotation.
    let field = 128 - rotation;
    0x0420_3400 | (((field >> 5) & 3) << 22) | (((field >> 3) & 3) << 19) | ((field & 7) << 16)
}

/// EOR3 Zdn.D, Zdn.D, Zm.D, Zk.D with zero register fields.
const EOR3_ENCODING: u32 = 0x0420_3800;

/// BCAX Zdn.D, Zdn.D, Zm.D, Zk.D with zero register fields.
const BCAX_ENCODING: u32 = 0x0460_3800;

#[cfg(test)]
mod tests {
    use super::{BCAX_ENCODING, EOR3_ENCODING, xar_encoding, xar64_encoding};

    #[test]
    fn test_xar_encoding() {
        // LLVM's assembler encodings for XAR Z0.S, Z0.S, Z0.S.
        assert_eq!(xar_encoding(16), 0x0470_3400);
        assert_eq!(xar_encoding(7), 0x0479_3400);
        // For 32-bit elements, tszh is 01 and the contiguous tszl:imm3 field at bits 16-20
        // holds 32 - rotation.
        for rotation in 1..32 {
            assert_eq!(
                xar_encoding(rotation),
                0x0460_3400 | ((32 - rotation) << 16),
                "rotation {rotation}"
            );
        }
        assert_eq!(xar_encoding(0), 0);
        assert_eq!(xar_encoding(32), 0);
    }

    /// Inserts the Zdn and Zm register numbers as the native XAR assembly does.
    const fn xar_registers(encoding: u32, dn: u32, m: u32) -> u32 {
        encoding + (m << 5) + dn
    }

    /// Inserts the Zdn, Zm, and Zk register numbers as the native EOR3 and BCAX assembly does.
    const fn bitwise3_registers(encoding: u32, dn: u32, m: u32, k: u32) -> u32 {
        encoding + (m << 16) + (k << 5) + dn
    }

    #[test]
    fn test_xar64_encoding() {
        // Words printed by objdump -d after assembling each instruction with
        // clang -target aarch64-linux-gnu -march=armv9-a+sve2 (Apple clang).
        assert_eq!(xar64_encoding(1), 0x04ff_3400); // xar z0.d, z0.d, z0.d, #1
        assert_eq!(xar64_encoding(32), 0x04e0_3400); // xar z0.d, z0.d, z0.d, #32
        assert_eq!(xar64_encoding(44), 0x04b4_3400); // xar z0.d, z0.d, z0.d, #44
        assert_eq!(xar64_encoding(63), 0x04a1_3400); // xar z0.d, z0.d, z0.d, #63
        // xar z0.d, z0.d, z1.d, #3
        assert_eq!(xar_registers(xar64_encoding(3), 0, 1), 0x04fd_3420);
        // xar z5.d, z5.d, z17.d, #14
        assert_eq!(xar_registers(xar64_encoding(14), 5, 17), 0x04f2_3625);
        // xar z31.d, z31.d, z30.d, #8
        assert_eq!(xar_registers(xar64_encoding(8), 31, 30), 0x04f8_37df);

        // For 64-bit elements, tszh<1> is 1, and the tszh<0>:tszl:imm3 field at bits 22,
        // 19-20, and 16-18 holds 64 - rotation.
        for rotation in 1..64 {
            let field = 64 - rotation;
            assert_eq!(
                xar64_encoding(rotation),
                0x04a0_3400 | ((field >> 5) << 22) | ((field & 31) << 16),
                "rotation {rotation}"
            );
        }
        assert_eq!(xar64_encoding(0), 0);
        assert_eq!(xar64_encoding(64), 0);
    }

    #[test]
    fn test_bitwise3_encoding() {
        // Words printed by objdump -d after assembling each instruction with
        // clang -target aarch64-linux-gnu -march=armv9-a+sve2 (Apple clang).
        // eor3 z0.d, z0.d, z0.d, z0.d
        assert_eq!(EOR3_ENCODING, 0x0420_3800);
        // eor3 z0.d, z0.d, z1.d, z2.d
        assert_eq!(bitwise3_registers(EOR3_ENCODING, 0, 1, 2), 0x0421_3840);
        // eor3 z7.d, z7.d, z19.d, z31.d
        assert_eq!(bitwise3_registers(EOR3_ENCODING, 7, 19, 31), 0x0433_3be7);
        // eor3 z31.d, z31.d, z3.d, z16.d
        assert_eq!(bitwise3_registers(EOR3_ENCODING, 31, 3, 16), 0x0423_3a1f);
        // bcax z0.d, z0.d, z0.d, z0.d
        assert_eq!(BCAX_ENCODING, 0x0460_3800);
        // bcax z0.d, z0.d, z1.d, z2.d
        assert_eq!(bitwise3_registers(BCAX_ENCODING, 0, 1, 2), 0x0461_3840);
        // bcax z7.d, z7.d, z19.d, z31.d
        assert_eq!(bitwise3_registers(BCAX_ENCODING, 7, 19, 31), 0x0473_3be7);
        // bcax z31.d, z31.d, z3.d, z16.d
        assert_eq!(bitwise3_registers(BCAX_ENCODING, 31, 3, 16), 0x0463_3a1f);
    }
}
