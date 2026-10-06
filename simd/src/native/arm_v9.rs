//! Native implementation of the Armv9-A SVE2 instruction profile.

use super::neon::NativeNeon;
use crate::{ArmV9, Neon, Operation, Simd};
use core::arch::asm;

/// Native Armv9 execution token with 16 byte, four u32, and two u64 lanes.
///
/// This profile includes NEON and SHA2 with fixed 128-bit logical vectors.
/// It does not expose scalable SVE vectors.
///
/// Construction checks NEON, SHA2, SVE, SVE2, and the calling thread's SVE vector
/// length. Only the low 128 bits are modeled, independently of the full SVE
/// width. All supported SVE vector lengths are at least 128 bits, so moving
/// a token to another thread does not invalidate its fixed lane counts.
#[derive(Clone, Copy, Debug)]
pub struct NativeArmV9(NativeNeon);

impl NativeArmV9 {
    /// Returns a token if NEON, SHA2, SVE, and SVE2 are available and this thread's
    /// SVE vector length contains the modeled 128 bits.
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
        if !supported {
            return None;
        }
        let bytes: usize;
        // SAFETY: SVE availability was checked above. CNTB X0 only reads this
        // thread's vector length and writes the declared general register.
        // The encoding avoids requiring SVE in the constructor's feature scope.
        unsafe {
            asm!(
                ".inst 0x0420e3e0",
                out("x0") bytes,
                options(nomem, nostack, preserves_flags),
            );
        }
        (bytes >= 16).then_some(Self(neon))
    }

    #[inline]
    #[target_feature(enable = "neon,sha2,sve,sve2")]
    unsafe fn execute_arm_v9<O: Operation<Self>>(self, operation: O) -> O::Output {
        operation.arm_v9(self)
    }
}

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
    fn u32_permute(self, value: Self::U32, indices: &[usize]) -> Self::U32 {
        self.0.u32_permute(value, indices)
    }

    #[inline]
    fn u32_permute2(self, a: Self::U32, b: Self::U32, indices: &[usize]) -> Self::U32 {
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
    fn u8_table_lookup(self, table: Self::U8, indices: Self::U8) -> Self::U8 {
        self.0.u8_table_lookup(table, indices)
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
        // SAFETY: Construction established NEON, SVE, and SVE2. The current
        // thread's SVE width is at least 128 bits. Vn aliases Zn's low 128 bits,
        // and XAR acts independently on 32-bit lanes, so arbitrary higher
        // source bits cannot affect the four modeled lanes. Only the declared
        // destination register is written; the source register is preserved.
        // The final NEON ORR preserves the low result and zeros every higher
        // destination bit, giving the same full-register effect as an ordinary
        // NEON output. No live upper SVE state is retained in a Rust U32 value.
        // Neither instruction accesses memory, the stack, or flags.
        #[cfg(target_feature = "neon")]
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
                "orr {dn:v}.16b, {dn:v}.16b, {dn:v}.16b",
                dn = inout(vreg) a,
                m = in(vreg) b,
                encoding = const xar_encoding(N),
                options(pure, nomem, nostack, preserves_flags),
            );
        }
        // SAFETY: The token still establishes NEON/SVE/SVE2 when the compiler's
        // baseline disables NEON. Explicit vector clobbers require no baseline
        // feature; LD1/ST1 access the live 128-bit locals through valid pointers.
        // XAR and the final ORR have the same lane and upper-register contract
        // as above. Both full vector aliases are clobbered, and flags are intact.
        #[cfg(not(target_feature = "neon"))]
        unsafe {
            let a_ptr = core::ptr::from_mut(&mut a);
            asm!(
                "ld1 {{v0.4s}}, [{a}]",
                "ld1 {{v1.4s}}, [{b}]",
                ".inst {encoding}",
                "orr v0.16b, v0.16b, v0.16b",
                "st1 {{v0.4s}}, [{a}]",
                a = in(reg) a_ptr,
                b = in(reg) core::ptr::from_ref(&b),
                encoding = const xar_encoding(N) + (1 << 5),
                out("v0") _,
                out("v1") _,
                options(nostack, preserves_flags),
            );
        }
        a
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

#[cfg(test)]
mod tests {
    use super::xar_encoding;

    #[test]
    fn test_xar_encoding() {
        // LLVM's assembler encodings for XAR Z0.S, Z0.S, Z0.S.
        assert_eq!(xar_encoding(16), 0x0470_3400);
        assert_eq!(xar_encoding(7), 0x0479_3400);
    }
}
