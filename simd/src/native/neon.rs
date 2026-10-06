//! Native implementation of the AArch64 NEON and SHA2 instruction profile.

use crate::{Neon, Operation, Simd};
use core::arch::aarch64::{
    uint8x16_t, uint8x16x2_t, uint16x8_t, uint32x2_t, uint32x4_t, uint64x2_t, vadd_u32, vaddq_u32,
    vaddq_u64, vandq_u8, vandq_u32, vandq_u64, vbslq_u32, vbslq_u64, vcombine_u8, vdup_n_s32,
    vdup_n_u8, vdup_n_u32, vdupq_n_s8, vdupq_n_s16, vdupq_n_s32, vdupq_n_s64, vdupq_n_u8,
    vdupq_n_u32, vdupq_n_u64, veorq_u8, veorq_u16, veorq_u32, veorq_u64, vextq_u8, vextq_u32,
    vget_high_u8, vget_low_u8, vgetq_lane_u8, vgetq_lane_u64, vld1_u8, vld1q_u8, vld1q_u32,
    vld1q_u64, vmlal_u32, vmovn_u16, vmovn_u64, vmull_p8, vmull_u32, vorrq_u32, vorrq_u64,
    vqtbl1q_u8, vqtbl2q_u8, vreinterpret_p8_u8, vreinterpretq_u8_u32, vreinterpretq_u16_p16,
    vreinterpretq_u32_u8, vrev32q_u8, vsetq_lane_u64, vsha256h2q_u32, vsha256hq_u32,
    vsha256su0q_u32, vsha256su1q_u32, vshl_u32, vshlq_u8, vshlq_u16, vshlq_u32, vshlq_u64,
    vst1q_u8, vst1q_u32, vst1q_u64, vsubq_u32, vsubq_u64,
};

/// Native NEON execution token with 16 byte, four u32, and two u64 lanes.
///
/// Constructed only after checking for NEON and SHA2 support. Copies preserve this guarantee,
/// so vector instructions and child operations need no additional feature checks.
///
/// # Examples
///
/// ```
/// # #[cfg(target_arch = "aarch64")]
/// # {
/// use commonware_simd::{native::NativeNeon, Simd};
///
/// if let Some(simd) = NativeNeon::new() {
///     let sum = simd.u64_add(simd.u64_load(&[1, u64::MAX]), simd.u64_splat(1));
///     let mut output = [0; 2];
///     simd.u64_store(sum, &mut output);
///     assert_eq!(output, [2, 0]);
/// }
/// # }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct NativeNeon(());

impl NativeNeon {
    #[inline]
    #[target_feature(enable = "neon,sha2")]
    unsafe fn sha256_h_native(
        self,
        abcd: uint32x4_t,
        efgh: uint32x4_t,
        wk: uint32x4_t,
    ) -> uint32x4_t {
        vsha256hq_u32(abcd, efgh, wk)
    }

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    unsafe fn sha256_h2_native(
        self,
        efgh: uint32x4_t,
        abcd: uint32x4_t,
        wk: uint32x4_t,
    ) -> uint32x4_t {
        vsha256h2q_u32(efgh, abcd, wk)
    }

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    unsafe fn sha256_su0_native(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        vsha256su0q_u32(a, b)
    }

    #[inline]
    #[target_feature(enable = "neon,sha2")]
    unsafe fn sha256_su1_native(self, a: uint32x4_t, b: uint32x4_t, c: uint32x4_t) -> uint32x4_t {
        vsha256su1q_u32(a, b, c)
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn u32x4_load_native(self, input: &[u32]) -> uint32x4_t {
        assert!(input.len() >= 4);
        // SAFETY: This entry enables the required feature. Slice bounds above establish
        // the readable or writable extent for unaligned memory operations.
        unsafe { vld1q_u32(input.as_ptr()) }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn u32x4_store_native(self, value: uint32x4_t, output: &mut [u32]) {
        assert!(output.len() >= 4);
        // SAFETY: This entry enables the required feature. Slice bounds above establish
        // the readable or writable extent for unaligned memory operations.
        unsafe { vst1q_u32(output.as_mut_ptr(), value) }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn u32x4_add_native(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        vaddq_u32(a, b)
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn u32x4_shuffle_native<const MASK: i32>(self, value: uint32x4_t) -> uint32x4_t {
        assert!((0..256).contains(&MASK));
        // SAFETY: This entry enables the required feature. Slice bounds above establish
        // the readable or writable extent for unaligned memory operations.
        unsafe {
            let indices: [u8; 16] =
                core::array::from_fn(|i| (4 * ((MASK >> (2 * (i / 4))) & 3)) as u8 + (i % 4) as u8);
            vreinterpretq_u32_u8(vqtbl1q_u8(
                vreinterpretq_u8_u32(value),
                vld1q_u8(indices.as_ptr()),
            ))
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn u32x4_load_be_native(self, input: &[u8]) -> uint32x4_t {
        assert!(input.len() >= 16);
        // SAFETY: This entry enables the required feature. Slice bounds above establish
        // the readable or writable extent for unaligned memory operations.
        unsafe {
            let bytes = vld1q_u8(input.as_ptr());
            #[cfg(target_endian = "little")]
            let bytes = vrev32q_u8(bytes);
            vreinterpretq_u32_u8(bytes)
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn u32x4_load_be2_native(self, input: &[u8]) -> uint32x4_t {
        assert!(input.len() >= 8);
        // SAFETY: This entry enables the required feature. Slice bounds above establish
        // the readable or writable extent for unaligned memory operations.
        unsafe {
            let bytes = vcombine_u8(vld1_u8(input.as_ptr()), vdup_n_u8(0));
            #[cfg(target_endian = "little")]
            let bytes = vrev32q_u8(bytes);
            vreinterpretq_u32_u8(bytes)
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn u32x4_store_be_native(self, value: uint32x4_t, output: &mut [u8]) {
        assert!(output.len() >= 16);
        // SAFETY: This entry enables the required feature. Slice bounds above establish
        // the readable or writable extent for unaligned memory operations.
        unsafe {
            let bytes = vreinterpretq_u8_u32(value);
            #[cfg(target_endian = "little")]
            let bytes = vrev32q_u8(bytes);
            vst1q_u8(output.as_mut_ptr(), bytes)
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn u32x4_align_native<const N: i32>(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        assert!((0..=4).contains(&N));
        match N {
            0 => a,
            1 => vextq_u32::<1>(a, b),
            2 => vextq_u32::<2>(a, b),
            3 => vextq_u32::<3>(a, b),
            4 => b,
            _ => unreachable!(),
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn u32x4_blend_native<const MASK: i32>(
        self,
        a: uint32x4_t,
        b: uint32x4_t,
    ) -> uint32x4_t {
        assert!((0..16).contains(&MASK));
        let mask: [u32; 4] =
            core::array::from_fn(|i| if MASK & (1 << i) != 0 { u32::MAX } else { 0 });
        // SAFETY: The local array contains four readable words; NEON is enabled by this entry.
        unsafe { vbslq_u32(vld1q_u32(mask.as_ptr()), b, a) }
    }

    /// Returns a token if the current CPU supports NEON and SHA2.
    ///
    /// Without `std`, both features must be enabled at compile time.
    pub fn new() -> Option<Self> {
        #[cfg(feature = "std")]
        {
            (std::arch::is_aarch64_feature_detected!("neon")
                && std::arch::is_aarch64_feature_detected!("sha2"))
            .then_some(Self(()))
        }
        #[cfg(not(feature = "std"))]
        {
            (cfg!(target_feature = "neon") && cfg!(target_feature = "sha2")).then_some(Self(()))
        }
    }
}

impl Simd for NativeNeon {
    type U32x4 = uint32x4_t;

    #[inline]
    fn u32x4_load(self, input: &[u32]) -> uint32x4_t {
        // SAFETY: Token construction established the entry's required features.
        unsafe { self.u32x4_load_native(input) }
    }

    #[inline]
    fn u32x4_store(self, value: uint32x4_t, output: &mut [u32]) {
        // SAFETY: Token construction established the entry's required features.
        unsafe { self.u32x4_store_native(value, output) }
    }

    #[inline]
    fn u32x4_add(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        // SAFETY: Token construction established the entry's required features.
        unsafe { self.u32x4_add_native(a, b) }
    }

    #[inline]
    fn u32x4_shuffle<const MASK: i32>(self, value: uint32x4_t) -> uint32x4_t {
        // SAFETY: Token construction established the entry's required features.
        unsafe { self.u32x4_shuffle_native::<MASK>(value) }
    }

    #[inline]
    fn u32x4_load_be(self, input: &[u8]) -> uint32x4_t {
        // SAFETY: Token construction established the entry's required features.
        unsafe { self.u32x4_load_be_native(input) }
    }

    #[inline]
    fn u32x4_load_be2(self, input: &[u8]) -> uint32x4_t {
        // SAFETY: Token construction established the entry's required features.
        unsafe { self.u32x4_load_be2_native(input) }
    }

    #[inline]
    fn u32x4_store_be(self, value: uint32x4_t, output: &mut [u8]) {
        // SAFETY: Token construction established the entry's required features.
        unsafe { self.u32x4_store_be_native(value, output) }
    }

    #[inline]
    fn u32x4_align<const N: i32>(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        // SAFETY: Token construction established the entry's required features.
        unsafe { self.u32x4_align_native::<N>(a, b) }
    }

    #[inline]
    fn u32x4_blend<const MASK: i32>(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        // SAFETY: Token construction established the entry's required features.
        unsafe { self.u32x4_blend_native::<MASK>(a, b) }
    }

    type U8 = uint8x16_t;
    type U32 = uint32x4_t;
    type U64 = uint64x2_t;
    const U8_LANES: usize = 16;
    const U32_LANES: usize = 4;
    const U64_LANES: usize = 2;

    #[inline]
    fn u8_load(self, input: &[u8]) -> uint8x16_t {
        assert!(input.len() >= 16);
        // The validated slice contains 16 readable lanes; vector alignment is not required.
        // SAFETY: Construction of this token established NEON support.
        unsafe { vld1q_u8(input.as_ptr()) }
    }

    #[inline]
    fn u8_store(self, value: uint8x16_t, output: &mut [u8]) {
        assert!(output.len() >= 16);
        // The validated slice contains 16 writable lanes; vector alignment is not required.
        // SAFETY: Construction of this token established NEON support.
        unsafe { vst1q_u8(output.as_mut_ptr(), value) }
    }

    #[inline]
    fn u8_splat(self, value: u8) -> uint8x16_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vdupq_n_u8(value) }
    }

    #[inline]
    fn u8_xor(self, a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { veorq_u8(a, b) }
    }

    #[inline]
    fn u8_and(self, a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vandq_u8(a, b) }
    }

    #[inline]
    fn u8_shl<const N: u32>(self, value: uint8x16_t) -> uint8x16_t {
        assert!(N < 8);
        // SAFETY: Construction of this token established NEON support.
        unsafe { vshlq_u8(value, vdupq_n_s8(N as i8)) }
    }

    #[inline]
    fn u8_shr<const N: u32>(self, value: uint8x16_t) -> uint8x16_t {
        assert!(N < 8);
        // SAFETY: Construction of this token established NEON support.
        unsafe { vshlq_u8(value, vdupq_n_s8(-(N as i8))) }
    }

    #[inline]
    fn u32_load(self, input: &[u32]) -> uint32x4_t {
        assert!(input.len() >= 4);
        // The validated slice contains 4 readable lanes; vector alignment is not required.
        // SAFETY: Construction of this token established NEON support.
        unsafe { vld1q_u32(input.as_ptr()) }
    }

    #[inline]
    fn u32_store(self, value: uint32x4_t, output: &mut [u32]) {
        assert!(output.len() >= 4);
        // The validated slice contains 4 writable lanes; vector alignment is not required.
        // SAFETY: Construction of this token established NEON support.
        unsafe { vst1q_u32(output.as_mut_ptr(), value) }
    }

    #[inline]
    fn u32_splat(self, value: u32) -> uint32x4_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vdupq_n_u32(value) }
    }

    #[inline]
    fn u32_xor(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { veorq_u32(a, b) }
    }

    #[inline]
    fn u32_and(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vandq_u32(a, b) }
    }

    #[inline]
    fn u32_or(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vorrq_u32(a, b) }
    }

    #[inline]
    fn u32_add(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vaddq_u32(a, b) }
    }

    #[inline]
    fn u32_sub(self, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vsubq_u32(a, b) }
    }

    #[inline]
    fn u32_shl<const N: u32>(self, value: uint32x4_t) -> uint32x4_t {
        assert!(N < 32);
        // SAFETY: Construction of this token established NEON support.
        unsafe { vshlq_u32(value, vdupq_n_s32(N as i32)) }
    }

    #[inline]
    fn u32_shr<const N: u32>(self, value: uint32x4_t) -> uint32x4_t {
        assert!(N < 32);
        // SAFETY: Construction of this token established NEON support.
        unsafe { vshlq_u32(value, vdupq_n_s32(-(N as i32))) }
    }

    #[inline]
    fn u64_load(self, input: &[u64]) -> uint64x2_t {
        assert!(input.len() >= 2);
        // The validated slice contains 2 readable lanes; vector alignment is not required.
        // SAFETY: Construction of this token established NEON support.
        unsafe { vld1q_u64(input.as_ptr()) }
    }

    #[inline]
    fn u64_store(self, value: uint64x2_t, output: &mut [u64]) {
        assert!(output.len() >= 2);
        // The validated slice contains 2 writable lanes; vector alignment is not required.
        // SAFETY: Construction of this token established NEON support.
        unsafe { vst1q_u64(output.as_mut_ptr(), value) }
    }

    #[inline]
    fn u64_splat(self, value: u64) -> uint64x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vdupq_n_u64(value) }
    }

    #[inline]
    fn u64_xor(self, a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { veorq_u64(a, b) }
    }

    #[inline]
    fn u64_and(self, a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vandq_u64(a, b) }
    }

    #[inline]
    fn u64_or(self, a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vorrq_u64(a, b) }
    }

    #[inline]
    fn u64_add(self, a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vaddq_u64(a, b) }
    }

    #[inline]
    fn u64_sub(self, a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vsubq_u64(a, b) }
    }

    #[inline]
    fn u64_shl<const N: u32>(self, value: uint64x2_t) -> uint64x2_t {
        assert!(N < 64);
        // SAFETY: Construction of this token established NEON support.
        unsafe { vshlq_u64(value, vdupq_n_s64(N as i64)) }
    }

    #[inline]
    fn u64_shr<const N: u32>(self, value: uint64x2_t) -> uint64x2_t {
        assert!(N < 64);
        // SAFETY: Construction of this token established NEON support.
        unsafe { vshlq_u64(value, vdupq_n_s64(-(N as i64))) }
    }

    #[inline]
    fn u8_load_partial(self, input: &[u8]) -> uint8x16_t {
        assert!(input.len() <= 16);
        let mut lanes = [0; 16];
        lanes[..input.len()].copy_from_slice(input);
        // SAFETY: The token establishes NEON support, and lanes contains 16 readable bytes.
        unsafe { vld1q_u8(lanes.as_ptr()) }
    }

    #[inline]
    fn u8_store_partial(self, value: uint8x16_t, output: &mut [u8]) {
        assert!(output.len() <= 16);
        let mut lanes = [0; 16];
        // SAFETY: The token establishes NEON support, and lanes contains 16 writable bytes.
        unsafe { vst1q_u8(lanes.as_mut_ptr(), value) };
        output.copy_from_slice(&lanes[..output.len()]);
    }

    #[inline]
    fn u8_xor_fold(self, value: uint8x16_t) -> u8 {
        // SAFETY: Construction of this token established NEON support.
        unsafe {
            let value = veorq_u8(value, vextq_u8::<8>(value, value));
            let value = veorq_u8(value, vextq_u8::<4>(value, value));
            let value = veorq_u8(value, vextq_u8::<2>(value, value));
            let value = veorq_u8(value, vextq_u8::<1>(value, value));
            vgetq_lane_u8::<0>(value)
        }
    }

    #[inline]
    fn u32_rotate_right<const N: u32>(self, value: uint32x4_t) -> uint32x4_t {
        assert!(N < 32);
        // SAFETY: Construction of this token established NEON support.
        unsafe {
            vorrq_u32(
                vshlq_u32(value, vdupq_n_s32(-(N as i32))),
                vshlq_u32(value, vdupq_n_s32((32 - N) as i32)),
            )
        }
    }

    #[inline]
    fn u32_select(self, mask: uint32x4_t, a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vbslq_u32(mask, a, b) }
    }

    #[inline]
    fn u64_select(self, mask: uint64x2_t, a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vbslq_u64(mask, a, b) }
    }

    #[inline]
    fn u32_permute(self, value: uint32x4_t, indices: &[usize]) -> uint32x4_t {
        assert!(indices.len() >= 4);
        let indices = &indices[..4];
        assert!(indices.iter().all(|&index| index < 4));
        let mut bytes = [0; 16];
        for (lane, &index) in indices.iter().enumerate() {
            for byte in 0..4 {
                bytes[4 * lane + byte] = (4 * index + byte) as u8;
            }
        }
        // bytes contains 16 readable indices, each selecting a validated source lane.
        // SAFETY: Construction of this token established NEON support.
        unsafe {
            vreinterpretq_u32_u8(vqtbl1q_u8(
                vreinterpretq_u8_u32(value),
                vld1q_u8(bytes.as_ptr()),
            ))
        }
    }

    #[inline]
    fn u32_permute2(self, a: uint32x4_t, b: uint32x4_t, indices: &[usize]) -> uint32x4_t {
        assert!(indices.len() >= 4);
        let indices = &indices[..4];
        assert!(indices.iter().all(|&index| index < 8));
        let mut bytes = [0; 16];
        for (lane, &index) in indices.iter().enumerate() {
            for byte in 0..4 {
                bytes[4 * lane + byte] = (4 * index + byte) as u8;
            }
        }
        // bytes contains 16 readable indices, each selecting a validated source lane.
        // SAFETY: Construction of this token established NEON support.
        unsafe {
            let table = uint8x16x2_t(vreinterpretq_u8_u32(a), vreinterpretq_u8_u32(b));
            vreinterpretq_u32_u8(vqtbl2q_u8(table, vld1q_u8(bytes.as_ptr())))
        }
    }

    #[inline]
    fn u64_extract<const N: usize>(self, value: uint64x2_t) -> u64 {
        assert!(N < 2);
        // SAFETY: Construction of this token established NEON support.
        unsafe {
            if N == 0 {
                vgetq_lane_u64::<0>(value)
            } else {
                vgetq_lane_u64::<1>(value)
            }
        }
    }

    #[inline]
    fn u64_insert<const N: usize>(self, value: uint64x2_t, lane: u64) -> uint64x2_t {
        assert!(N < 2);
        // SAFETY: Construction of this token established NEON support.
        unsafe {
            if N == 0 {
                vsetq_lane_u64::<0>(lane, value)
            } else {
                vsetq_lane_u64::<1>(lane, value)
            }
        }
    }

    #[inline]
    fn execute<O: Operation<Self>>(self, operation: O) -> O::Output {
        #[inline]
        #[target_feature(enable = "neon,sha2")]
        unsafe fn execute_neon<O: Operation<NativeNeon>>(
            simd: NativeNeon,
            operation: O,
        ) -> O::Output {
            operation.neon(simd)
        }

        // SAFETY: Construction of this token established NEON and SHA2 support.
        unsafe { execute_neon(self, operation) }
    }
}

impl Neon for NativeNeon {
    #[inline]
    fn sha256_h(self, abcd: Self::U32x4, efgh: Self::U32x4, wk: Self::U32x4) -> Self::U32x4 {
        // SAFETY: The private token's constructor checked NEON and SHA2.
        unsafe { self.sha256_h_native(abcd, efgh, wk) }
    }

    #[inline]
    fn sha256_h2(self, efgh: Self::U32x4, abcd: Self::U32x4, wk: Self::U32x4) -> Self::U32x4 {
        // SAFETY: The private token's constructor checked NEON and SHA2.
        unsafe { self.sha256_h2_native(efgh, abcd, wk) }
    }

    #[inline]
    fn sha256_su0(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
        // SAFETY: The private token's constructor checked NEON and SHA2.
        unsafe { self.sha256_su0_native(a, b) }
    }

    #[inline]
    fn sha256_su1(self, a: Self::U32x4, b: Self::U32x4, c: Self::U32x4) -> Self::U32x4 {
        // SAFETY: The private token's constructor checked NEON and SHA2.
        unsafe { self.sha256_su1_native(a, b, c) }
    }

    type U16 = uint16x8_t;
    type U32Half = uint32x2_t;

    #[inline]
    fn u8_table_lookup(self, table: uint8x16_t, indices: uint8x16_t) -> uint8x16_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vqtbl1q_u8(table, indices) }
    }

    #[inline]
    fn u8_clmul_lo(self, a: uint8x16_t, b: uint8x16_t) -> uint16x8_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe {
            vreinterpretq_u16_p16(vmull_p8(
                vreinterpret_p8_u8(vget_low_u8(a)),
                vreinterpret_p8_u8(vget_low_u8(b)),
            ))
        }
    }

    #[inline]
    fn u8_clmul_hi(self, a: uint8x16_t, b: uint8x16_t) -> uint16x8_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe {
            vreinterpretq_u16_p16(vmull_p8(
                vreinterpret_p8_u8(vget_high_u8(a)),
                vreinterpret_p8_u8(vget_high_u8(b)),
            ))
        }
    }

    #[inline]
    fn u16_xor(self, a: uint16x8_t, b: uint16x8_t) -> uint16x8_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { veorq_u16(a, b) }
    }

    #[inline]
    fn u16_shl<const N: u32>(self, value: uint16x8_t) -> uint16x8_t {
        assert!(N < 16);
        // SAFETY: Construction of this token established NEON support.
        unsafe { vshlq_u16(value, vdupq_n_s16(N as i16)) }
    }

    #[inline]
    fn u16_shr<const N: u32>(self, value: uint16x8_t) -> uint16x8_t {
        assert!(N < 16);
        // SAFETY: Construction of this token established NEON support.
        unsafe { vshlq_u16(value, vdupq_n_s16(-(N as i16))) }
    }

    #[inline]
    fn u16_narrow_pair(self, low: uint16x8_t, high: uint16x8_t) -> uint8x16_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vcombine_u8(vmovn_u16(low), vmovn_u16(high)) }
    }

    #[inline]
    fn u64_narrow(self, value: uint64x2_t) -> uint32x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vmovn_u64(value) }
    }

    #[inline]
    fn u32_half_splat(self, value: u32) -> uint32x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vdup_n_u32(value) }
    }

    #[inline]
    fn u32_half_add(self, a: uint32x2_t, b: uint32x2_t) -> uint32x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vadd_u32(a, b) }
    }

    #[inline]
    fn u32_half_shl<const N: u32>(self, value: uint32x2_t) -> uint32x2_t {
        assert!(N < 32);
        // SAFETY: Construction of this token established NEON support.
        unsafe { vshl_u32(value, vdup_n_s32(N as i32)) }
    }

    #[inline]
    fn u32_widen_mul(self, a: uint32x2_t, b: uint32x2_t) -> uint64x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vmull_u32(a, b) }
    }

    #[inline]
    fn u32_widen_madd(self, acc: uint64x2_t, a: uint32x2_t, b: uint32x2_t) -> uint64x2_t {
        // SAFETY: Construction of this token established NEON support.
        unsafe { vmlal_u32(acc, a, b) }
    }
}

#[cfg(test)]
mod tests {
    //! Native NEON memory and arithmetic boundary tests.

    use super::NativeNeon;
    use crate::{Neon, Operation, Simd, emulated::EmulatedNeon};
    use core::arch::aarch64::{uint64x2_t, vdupq_n_u64, vgetq_lane_u64, vsetq_lane_u64};
    #[cfg(test)]
    use std::{
        eprintln,
        panic::{AssertUnwindSafe, catch_unwind},
    };

    const BOUNDARIES: [u64; 8] = [
        0,
        1,
        u64::MAX,
        u64::MAX - 1,
        1 << 63,
        (1 << 63) - 1,
        0xaaaa_aaaa_aaaa_aaaa,
        0x5555_5555_5555_5555,
    ];

    // Offset one is u64-aligned but deliberately not aligned to a NEON vector.
    #[repr(align(16))]
    struct Memory([u64; 5]);

    #[target_feature(enable = "neon")]
    unsafe fn extract_lanes(value: uint64x2_t) -> [u64; 2] {
        [vgetq_lane_u64::<0>(value), vgetq_lane_u64::<1>(value)]
    }

    fn native_lanes(_: NativeNeon, value: uint64x2_t) -> [u64; 2] {
        // SAFETY: Construction of the token established NEON support.
        unsafe { extract_lanes(value) }
    }

    #[target_feature(enable = "neon")]
    unsafe fn construct_vector(value: [u64; 2]) -> uint64x2_t {
        vsetq_lane_u64::<1>(value[1], vdupq_n_u64(value[0]))
    }

    fn native_vector(_: NativeNeon, value: [u64; 2]) -> uint64x2_t {
        // SAFETY: Construction of the token established NEON support.
        unsafe { construct_vector(value) }
    }

    fn output<S: Simd>(simd: S, value: S::U64, sentinel: u64) -> [u64; 5] {
        let mut memory = Memory([sentinel; 5]);
        simd.u64_store(value, &mut memory.0[1..]);
        memory.0
    }

    fn check_load(native: NativeNeon, value: [u64; 2], sentinel: u64) {
        let input = Memory([sentinel, value[0], value[1], !sentinel, sentinel]);
        let emulated = EmulatedNeon.u64_load(&input.0[1..]);
        assert_eq!(emulated, value);
        assert_eq!(
            native_lanes(native, native.u64_load(&input.0[1..])),
            emulated
        );
    }

    fn check_store(native: NativeNeon, value: [u64; 2], sentinel: u64) {
        let expected = [sentinel, value[0], value[1], sentinel, sentinel];
        assert_eq!(
            output(native, native_vector(native, value), sentinel),
            expected
        );
        assert_eq!(output(EmulatedNeon, value, sentinel), expected);
        assert_eq!(
            output(native, native_vector(native, value), sentinel),
            output(EmulatedNeon, value, sentinel)
        );
    }

    fn check_splat(native: NativeNeon, value: u64, sentinel: u64) {
        let emulated = EmulatedNeon.u64_splat(value);
        assert_eq!(emulated, [value; 2]);
        assert_eq!(native_lanes(native, native.u64_splat(value)), emulated);
        assert_eq!(
            output(native, native.u64_splat(value), sentinel),
            [sentinel, value, value, sentinel, sentinel]
        );
    }

    fn check_add(native: NativeNeon, a: [u64; 2], b: [u64; 2], sentinel: u64) {
        let expected = [
            sentinel,
            a[0].wrapping_add(b[0]),
            a[1].wrapping_add(b[1]),
            sentinel,
            sentinel,
        ];
        let actual = native.u64_add(native_vector(native, a), native_vector(native, b));
        let emulated = EmulatedNeon.u64_add(a, b);
        assert_eq!(native_lanes(native, actual), emulated);
        assert_eq!(output(native, actual, sentinel), expected);
        assert_eq!(output(EmulatedNeon, emulated, sentinel), expected);
    }

    #[cfg(test)]
    fn check_short<S: Simd>(simd: S, value: u64, len: usize) {
        let mut memory = Memory([value; 5]);
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_load(&memory.0[1..1 + len]))).is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                simd.u64_store(simd.u64_splat(!value), &mut memory.0[1..1 + len]);
            }))
            .is_err()
        );
        assert_eq!(memory.0, [value; 5]);
    }

    #[derive(Clone, Copy)]
    struct Child([u64; 2]);

    impl<S: Simd> Operation<S> for Child {
        type Output = (bool, [u64; 2]);

        fn portable(self, _: S) -> Self::Output {
            (false, self.0)
        }

        fn neon(self, simd: S) -> Self::Output
        where
            S: Neon,
        {
            let value = simd.u64_add(simd.u64_load(&self.0), simd.u64_splat(1));
            let mut result = [0; 2];
            simd.u64_store(value, &mut result);
            (true, result)
        }
    }

    struct Parent<O>(O);

    impl<S: Simd, O: Operation<S>> Operation<S> for Parent<O> {
        type Output = O::Output;

        fn portable(self, simd: S) -> Self::Output {
            execute_child(simd, self.0)
        }
    }

    fn execute_child<S: Simd, O: Operation<S>>(simd: S, child: O) -> O::Output {
        simd.execute(child)
    }

    fn check_execute(native: NativeNeon, value: [u64; 2]) {
        let expected = (true, value.map(|v| v.wrapping_add(1)));
        assert_eq!(
            native.execute(Child(value)),
            EmulatedNeon.execute(Child(value))
        );
        assert_eq!(
            native.execute(Parent(Parent(Child(value)))),
            EmulatedNeon.execute(Parent(Parent(Child(value))))
        );
        assert_eq!(native.execute(Child(value)), expected);
        assert_eq!(EmulatedNeon.execute(Child(value)), expected);
        assert_eq!(native.execute(Parent(Parent(Child(value)))), expected);
        assert_eq!(EmulatedNeon.execute(Parent(Parent(Child(value)))), expected);
    }

    #[test]
    fn test_boundaries() {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            eprintln!("skipping native NEON boundaries: NEON is unavailable");
            return;
        }
        let native = NativeNeon::new().expect("NEON hardware must yield a token");
        for a in BOUNDARIES {
            check_splat(native, a, !a);
            check_execute(native, [a, !a]);
            for b in BOUNDARIES {
                check_load(native, [a, b], !a);
                check_store(native, [a, b], !a);
                check_add(native, [a, b], [b, a], !a);
            }
            for len in 0..2 {
                check_short(native, a, len);
                check_short(EmulatedNeon, a, len);
            }
        }
    }
}

#[cfg(test)]
mod sha_tests {
    use super::*;
    use crate::emulated::EmulatedNeon;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn words(simd: NativeNeon, value: <NativeNeon as Simd>::U32x4) -> [u32; 4] {
        let mut output = [0; 4];
        simd.u32x4_store(value, &mut output);
        output
    }

    #[test]
    fn test_sha256_native_matches_emulated() {
        let Some(simd) = NativeNeon::new() else {
            return;
        };
        let emulated = EmulatedNeon;
        for seed in [0u32, 1, u32::MAX, 0x8000_0000, 0x1234_5678] {
            for step in 0..128u32 {
                let a: [u32; 4] = core::array::from_fn(|i| {
                    seed.wrapping_add((i as u32).wrapping_mul(0x9e37_79b9))
                        .rotate_right(step % 32)
                });
                let b = a.map(|v| v.wrapping_mul(0x7654_3211).wrapping_add(step));
                let c = b.map(|v| !v.rotate_right(13));
                let av = simd.u32x4_load(&a);
                let bv = simd.u32x4_load(&b);
                let cv = simd.u32x4_load(&c);
                assert_eq!(
                    words(simd, simd.sha256_h(av, bv, cv)),
                    emulated.sha256_h(a, b, c)
                );
                assert_eq!(
                    words(simd, simd.sha256_h2(bv, av, cv)),
                    emulated.sha256_h2(b, a, c)
                );
                assert_eq!(
                    words(simd, simd.sha256_su0(av, bv)),
                    emulated.sha256_su0(a, b)
                );
                assert_eq!(
                    words(simd, simd.sha256_su1(av, bv, cv)),
                    emulated.sha256_su1(a, b, c)
                );
                assert_eq!(
                    words(simd, simd.u32x4_add(av, bv)),
                    emulated.u32x4_add(a, b)
                );
                assert_eq!(
                    words(simd, simd.u32x4_shuffle::<0x1b>(av)),
                    emulated.u32x4_shuffle::<0x1b>(a)
                );
                macro_rules! align { ($($n:literal),*) => { $(
                    assert_eq!(words(simd, simd.u32x4_align::<$n>(av, bv)), emulated.u32x4_align::<$n>(a, b));
                )* }; }
                align!(0, 1, 2, 3, 4);
                macro_rules! blend { ($($n:literal),*) => { $(
                    assert_eq!(words(simd, simd.u32x4_blend::<$n>(av, bv)), emulated.u32x4_blend::<$n>(a, b));
                )* }; }
                blend!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            }
        }
    }

    #[test]
    fn test_sha_register_native_memory() {
        let Some(simd) = NativeNeon::new() else {
            return;
        };
        let emulated = EmulatedNeon;
        let input: [u8; 33] = core::array::from_fn(|i| (i as u8).wrapping_mul(73));
        for offset in 0..16 {
            let bytes = &input[offset..];
            let value = simd.u32x4_load_be(bytes);
            assert_eq!(words(simd, value), emulated.u32x4_load_be(bytes));
            assert_eq!(
                words(simd, simd.u32x4_load_be2(bytes)),
                emulated.u32x4_load_be2(bytes)
            );
            let mut output = [0xa5; 18];
            simd.u32x4_store_be(value, &mut output[1..]);
            assert_eq!(&output[1..17], &bytes[..16]);
            assert_eq!((output[0], output[17]), (0xa5, 0xa5));
        }
        let value = simd.u32x4_load(&[u32::MAX; 4]);
        let input_words = [0, u32::MAX, 0x8000_0000, 0x1234_5678, 1, 0];
        let loaded = simd.u32x4_load(&input_words[1..]);
        let mut output = [0xa5; 6];
        simd.u32x4_store(loaded, &mut output[1..]);
        assert_eq!(&output[1..5], &input_words[1..5]);
        assert_eq!((output[0], output[5]), (0xa5, 0xa5));
        for len in 0..4 {
            assert!(catch_unwind(|| simd.u32x4_load(&input_words[..len])).is_err());
            let mut output = [0xa5; 4];
            assert!(
                catch_unwind(AssertUnwindSafe(
                    || simd.u32x4_store(loaded, &mut output[..len])
                ))
                .is_err()
            );
            assert_eq!(output, [0xa5; 4]);
        }
        for len in 0..16 {
            assert!(catch_unwind(|| simd.u32x4_load_be(&input[..len])).is_err());
            if len < 8 {
                assert!(catch_unwind(|| simd.u32x4_load_be2(&input[..len])).is_err());
            }
            let mut output = [0xa5; 16];
            assert!(
                catch_unwind(AssertUnwindSafe(
                    || simd.u32x4_store_be(value, &mut output[..len])
                ))
                .is_err()
            );
            assert_eq!(output, [0xa5; 16]);
        }
    }

    #[test]
    fn test_sha2_native_execution_path() {
        let Some(simd) = NativeNeon::new() else {
            return;
        };
        struct Path;
        impl<S: Simd> Operation<S> for Path {
            type Output = bool;
            fn portable(self, _: S) -> bool {
                false
            }
            fn neon(self, _: S) -> bool
            where
                S: Neon,
            {
                true
            }
        }
        assert!(simd.execute(Path));
    }
}
