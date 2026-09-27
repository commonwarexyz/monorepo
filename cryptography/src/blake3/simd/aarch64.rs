//! NEON kernels.
//!
//! Batches hash eight messages with two NEON vectors per word, so two
//! independent mixing chains fill the vector pipes that one four-lane chain
//! leaves idle. When SVE2 is available, their 12, 8, and 7 bit xor-rotates use
//! the `XAR` instruction. Partial batches use four-lane words, whose fused
//! xor-rotates all use `XAR` when available. Pairs use duplicated words and
//! the SHA-3 extension's `XAR` when available.
//!
//! A single message of two or more chunks hashes its chunks in the same lanes,
//! with a separate chunk counter per lane, and merges their chaining values
//! level by level in lanes.

use super::{Digest, Words, batch};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blake3::{
    BLOCK_LEN, CHUNK_LEN, OUT_LEN,
    hazmat::{ChainingValue, HasherExt, Mode, merge_subtrees_non_root, merge_subtrees_root},
};
use core::arch::{aarch64::*, asm};

/// Messages per NEON vector.
const LANES: usize = 4;

/// Minimum active lanes for the batch kernel.
const MINIMUM: usize = 2;

/// Byte shuffle rotating each 32-bit word right by 8 bits.
static ROTATE8: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];

/// Rotate each 32-bit lane right by 16 bits.
#[inline(always)]
unsafe fn rotate16(x: uint32x4_t) -> uint32x4_t {
    // SAFETY: The caller establishes NEON.
    unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))) }
}

/// Rotate each 32-bit lane right by 8 bits.
#[inline(always)]
unsafe fn rotate8(x: uint32x4_t) -> uint32x4_t {
    // SAFETY: The caller establishes NEON, and the table is 16 bytes.
    unsafe {
        let table = vld1q_u8(ROTATE8.as_ptr());
        vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), table))
    }
}

/// Rotate each 32-bit lane right by `R` bits (`L` must be `32 - R`) with a
/// shift left and a shift right and insert.
///
/// The insert is written in assembly because LLVM rewrites the intrinsic
/// form of this idiom as a shift left and an accumulating shift right, which
/// has a longer dependency chain on Neoverse V2.
#[inline(always)]
unsafe fn rotate<const R: u32, const L: i32>(x: uint32x4_t) -> uint32x4_t {
    // SAFETY: The caller establishes NEON. The assembly only reads and
    // writes the two vector registers.
    unsafe {
        let mut high = vshlq_n_u32::<L>(x);
        asm!(
            "sri {high:v}.4s, {x:v}.4s, #{r}",
            high = inout(vreg) high,
            x = in(vreg) x,
            r = const R,
            options(pure, nomem, nostack, preserves_flags),
        );
        high
    }
}

/// Interleave the 64-bit halves of `low` and `high`.
#[inline(always)]
unsafe fn interleave(low: uint32x4_t, high: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
    // SAFETY: The caller establishes NEON.
    unsafe {
        let (low, high) = (vreinterpretq_u64_u32(low), vreinterpretq_u64_u32(high));
        (
            vreinterpretq_u32_u64(vtrn1q_u64(low, high)),
            vreinterpretq_u32_u64(vtrn2q_u64(low, high)),
        )
    }
}

/// Transpose a 4x4 matrix of words held as four row vectors.
#[inline(always)]
unsafe fn transpose(rows: [uint32x4_t; 4]) -> [uint32x4_t; 4] {
    // SAFETY: The caller establishes NEON.
    unsafe {
        let ab_02 = vtrn1q_u32(rows[0], rows[1]);
        let ab_13 = vtrn2q_u32(rows[0], rows[1]);
        let cd_02 = vtrn1q_u32(rows[2], rows[3]);
        let cd_13 = vtrn2q_u32(rows[2], rows[3]);
        let (abcd_0, abcd_2) = interleave(ab_02, cd_02);
        let (abcd_1, abcd_3) = interleave(ab_13, cd_13);
        [abcd_0, abcd_1, abcd_2, abcd_3]
    }
}

/// Load and transpose 16 bytes at `offset` of each block.
#[inline(always)]
unsafe fn quarter(blocks: [&[u8; BLOCK_LEN]; LANES], offset: usize) -> [uint32x4_t; 4] {
    // SAFETY: The caller establishes NEON and passes an offset of at most 48,
    // so each 16-byte load stays within its 64-byte block.
    unsafe {
        transpose([
            vreinterpretq_u32_u8(vld1q_u8(blocks[0][offset..].as_ptr())),
            vreinterpretq_u32_u8(vld1q_u8(blocks[1][offset..].as_ptr())),
            vreinterpretq_u32_u8(vld1q_u8(blocks[2][offset..].as_ptr())),
            vreinterpretq_u32_u8(vld1q_u8(blocks[3][offset..].as_ptr())),
        ])
    }
}

impl Words<LANES> for uint32x4_t {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { vdupq_n_u32(word) }
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { vaddq_u32(self, other) }
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { veorq_u32(self, other) }
    }

    #[inline(always)]
    unsafe fn xor_rotate16(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { rotate16(veorq_u32(self, other)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate12(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { rotate::<12, 20>(veorq_u32(self, other)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate8(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { rotate8(veorq_u32(self, other)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate7(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { rotate::<7, 25>(veorq_u32(self, other)) }
    }

    #[inline(always)]
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; LANES]) -> [Self; 16] {
        // SAFETY: The caller establishes NEON, and each quarter offset is at
        // most 48.
        unsafe {
            let [q0, q1, q2, q3] = [
                quarter(blocks, 0),
                quarter(blocks, 16),
                quarter(blocks, 32),
                quarter(blocks, 48),
            ];
            [
                q0[0], q0[1], q0[2], q0[3], q1[0], q1[1], q1[2], q1[3], q2[0], q2[1], q2[2], q2[3],
                q3[0], q3[1], q3[2], q3[3],
            ]
        }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; LANES] {
        // SAFETY: The caller establishes NEON, and each 16-byte store starts
        // at offset 0 or 16 of a 32-byte output.
        unsafe {
            let low = transpose([words[0], words[1], words[2], words[3]]);
            let high = transpose([words[4], words[5], words[6], words[7]]);
            let mut outputs = [[0u8; OUT_LEN]; LANES];
            for ((output, low), high) in outputs.iter_mut().zip(low).zip(high) {
                vst1q_u8(output.as_mut_ptr(), vreinterpretq_u8_u32(low));
                vst1q_u8(output[16..].as_mut_ptr(), vreinterpretq_u8_u32(high));
            }
            outputs
        }
    }
}

/// NEON words whose fused xor-rotates use the SVE2 `XAR` instruction.
///
/// `XAR` exclusive-ors two vectors and rotates each lane in one instruction,
/// replacing two or three NEON instructions on the critical path of every
/// mixing step. NEON registers alias the low 128 bits of the SVE registers,
/// and a NEON write zeroes the rest, so `XAR` on the aliased registers gives
/// the NEON result at any SVE vector length.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct Xar(uint32x4_t);

/// Encode `XAR Zdn.S, Zdn.S, Zm.S, #rotation` with both register fields zero.
const fn xar_encoding(rotation: u32) -> u32 {
    // The 32-bit element size and the rotation share one 7-bit field that
    // holds `64 - rotation`, split across bits 22-23, 19-20, and 16-18.
    let field = 64 - rotation;
    0x0420_3400 | (((field >> 5) & 3) << 22) | (((field >> 3) & 3) << 19) | ((field & 7) << 16)
}

/// Exclusive-or `dn` and `m`, then rotate each 32-bit lane right by `R` bits,
/// with the SVE2 `XAR` instruction on the aliased SVE registers.
///
/// Rust's inline assembly cannot name SVE registers, so the instruction is
/// emitted by encoding, with the register numbers recovered from the NEON
/// register names the compiler assigns.
#[inline(always)]
unsafe fn xar<const R: u32>(mut dn: uint32x4_t, m: uint32x4_t) -> uint32x4_t {
    // SAFETY: The caller establishes SVE2. The assembly only reads and writes
    // the two vector registers, and `XAR` leaves the destination's high bits
    // zero when both sources have zero high bits.
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
            dn = inout(vreg) dn,
            m = in(vreg) m,
            encoding = const xar_encoding(R),
            options(pure, nomem, nostack, preserves_flags),
        );
    }
    dn
}

impl Words<LANES> for Xar {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(vdupq_n_u32(word)) }
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(vaddq_u32(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(veorq_u32(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate16(self, other: Self) -> Self {
        // SAFETY: The caller establishes SVE2.
        unsafe { Self(xar::<16>(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate12(self, other: Self) -> Self {
        // SAFETY: The caller establishes SVE2.
        unsafe { Self(xar::<12>(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate8(self, other: Self) -> Self {
        // SAFETY: The caller establishes SVE2.
        unsafe { Self(xar::<8>(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate7(self, other: Self) -> Self {
        // SAFETY: The caller establishes SVE2.
        unsafe { Self(xar::<7>(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; LANES]) -> [Self; 16] {
        // SAFETY: The caller establishes NEON.
        unsafe { <uint32x4_t as Words<LANES>>::load(blocks).map(Self) }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; LANES] {
        // SAFETY: The caller establishes NEON.
        unsafe { <uint32x4_t as Words<LANES>>::store(words.map(|word| word.0)) }
    }
}

/// NEON words that use the SVE2 `XAR` instruction for the 12, 8, and 7 bit
/// xor-rotates and `REV32` for the 16 bit one.
///
/// Eight-lane batches have enough independent work to be limited by
/// instruction throughput rather than latency. Keeping one xor-rotate per
/// mixing step off `XAR` balances the load on cores that issue `XAR` on fewer
/// pipes than plain vector instructions, while still removing most of the
/// shift sequences.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct Hybrid(uint32x4_t);

impl Words<LANES> for Hybrid {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(vdupq_n_u32(word)) }
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(vaddq_u32(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(veorq_u32(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate16(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(rotate16(veorq_u32(self.0, other.0))) }
    }

    #[inline(always)]
    unsafe fn xor_rotate12(self, other: Self) -> Self {
        // SAFETY: The caller establishes SVE2.
        unsafe { Self(xar::<12>(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate8(self, other: Self) -> Self {
        // SAFETY: The caller establishes SVE2.
        unsafe { Self(xar::<8>(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate7(self, other: Self) -> Self {
        // SAFETY: The caller establishes SVE2.
        unsafe { Self(xar::<7>(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; LANES]) -> [Self; 16] {
        // SAFETY: The caller establishes NEON.
        unsafe { <uint32x4_t as Words<LANES>>::load(blocks).map(Self) }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; LANES] {
        // SAFETY: The caller establishes NEON.
        unsafe { <uint32x4_t as Words<LANES>>::store(words.map(|word| word.0)) }
    }
}

/// Two four-lane words hashed side by side: eight messages whose independent
/// mixing chains fill the vector pipes one four-lane chain leaves idle.
#[derive(Clone, Copy)]
struct Dual<W>([W; 2]);

impl<W: Words<LANES>> Words<{ 2 * LANES }> for Dual<W> {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        // SAFETY: The caller establishes the target features `W` requires.
        unsafe { Self([W::splat(word); 2]) }
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        let ([a, b], [c, d]) = (self.0, other.0);
        // SAFETY: The caller establishes the target features `W` requires.
        unsafe { Self([a.add(c), b.add(d)]) }
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        let ([a, b], [c, d]) = (self.0, other.0);
        // SAFETY: The caller establishes the target features `W` requires.
        unsafe { Self([a.xor(c), b.xor(d)]) }
    }

    #[inline(always)]
    unsafe fn xor_rotate16(self, other: Self) -> Self {
        let ([a, b], [c, d]) = (self.0, other.0);
        // SAFETY: The caller establishes the target features `W` requires.
        unsafe { Self([a.xor_rotate16(c), b.xor_rotate16(d)]) }
    }

    #[inline(always)]
    unsafe fn xor_rotate12(self, other: Self) -> Self {
        let ([a, b], [c, d]) = (self.0, other.0);
        // SAFETY: The caller establishes the target features `W` requires.
        unsafe { Self([a.xor_rotate12(c), b.xor_rotate12(d)]) }
    }

    #[inline(always)]
    unsafe fn xor_rotate8(self, other: Self) -> Self {
        let ([a, b], [c, d]) = (self.0, other.0);
        // SAFETY: The caller establishes the target features `W` requires.
        unsafe { Self([a.xor_rotate8(c), b.xor_rotate8(d)]) }
    }

    #[inline(always)]
    unsafe fn xor_rotate7(self, other: Self) -> Self {
        let ([a, b], [c, d]) = (self.0, other.0);
        // SAFETY: The caller establishes the target features `W` requires.
        unsafe { Self([a.xor_rotate7(c), b.xor_rotate7(d)]) }
    }

    #[inline(always)]
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; 2 * LANES]) -> [Self; 16] {
        let (low, high) = blocks.split_at(LANES);
        // SAFETY: The caller establishes the target features `W` requires.
        unsafe {
            let low = W::load(low.try_into().expect("half of the blocks"));
            let high = W::load(high.try_into().expect("half of the blocks"));
            core::array::from_fn(|word| Self([low[word], high[word]]))
        }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; 2 * LANES] {
        // SAFETY: The caller establishes the target features `W` requires.
        unsafe {
            let low = W::store(words.map(|word| word.0[0]));
            let high = W::store(words.map(|word| word.0[1]));
            core::array::from_fn(|lane| {
                if lane < LANES {
                    low[lane]
                } else {
                    high[lane - LANES]
                }
            })
        }
    }
}

/// Two messages per NEON vector, each 32-bit word duplicated across a 64-bit
/// lane.
///
/// Rotating a 64-bit lane that holds a 32-bit word twice rotates both copies
/// by the same amount, so the SHA-3 extension's 64-bit `XAR` performs each
/// fused xor-rotate in one instruction. Additions and exclusive-ors act on
/// the copies independently and keep them equal.
#[derive(Clone, Copy)]
struct Dup(uint32x4_t);

impl Words<2> for Dup {
    #[inline(always)]
    unsafe fn splat(word: u32) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(vdupq_n_u32(word)) }
    }

    #[inline(always)]
    unsafe fn add(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(vaddq_u32(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor(self, other: Self) -> Self {
        // SAFETY: The caller establishes NEON.
        unsafe { Self(veorq_u32(self.0, other.0)) }
    }

    #[inline(always)]
    unsafe fn xor_rotate16(self, other: Self) -> Self {
        // SAFETY: The caller establishes the SHA-3 extension.
        unsafe { self.xar::<16>(other) }
    }

    #[inline(always)]
    unsafe fn xor_rotate12(self, other: Self) -> Self {
        // SAFETY: The caller establishes the SHA-3 extension.
        unsafe { self.xar::<12>(other) }
    }

    #[inline(always)]
    unsafe fn xor_rotate8(self, other: Self) -> Self {
        // SAFETY: The caller establishes the SHA-3 extension.
        unsafe { self.xar::<8>(other) }
    }

    #[inline(always)]
    unsafe fn xor_rotate7(self, other: Self) -> Self {
        // SAFETY: The caller establishes the SHA-3 extension.
        unsafe { self.xar::<7>(other) }
    }

    #[inline(always)]
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; 2]) -> [Self; 16] {
        // SAFETY: The caller establishes NEON, and each 16-byte load starts at
        // offset 0, 16, 32, or 48 of a 64-byte block.
        unsafe {
            let mut words = [Self(vdupq_n_u32(0)); 16];
            for quarter in 0..4 {
                let offset = quarter * 16;
                let left = vld1q_u32(blocks[0][offset..].as_ptr().cast());
                let right = vld1q_u32(blocks[1][offset..].as_ptr().cast());

                // Pair the messages' words, then duplicate each pair member.
                let low = vzip1q_u32(left, right);
                let high = vzip2q_u32(left, right);
                words[4 * quarter] = Self(vzip1q_u32(low, low));
                words[4 * quarter + 1] = Self(vzip2q_u32(low, low));
                words[4 * quarter + 2] = Self(vzip1q_u32(high, high));
                words[4 * quarter + 3] = Self(vzip2q_u32(high, high));
            }
            words
        }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; 2] {
        // SAFETY: The caller establishes NEON, and each 16-byte store starts
        // at offset 0 or 16 of a 32-byte output.
        unsafe {
            let mut outputs = [[0u8; OUT_LEN]; 2];
            for half in 0..2 {
                // Keep one copy of each word, then separate the messages.
                let w = &words[4 * half..4 * half + 4];
                let low = vuzp1q_u32(w[0].0, w[1].0);
                let high = vuzp1q_u32(w[2].0, w[3].0);
                let left = vuzp1q_u32(low, high);
                let right = vuzp2q_u32(low, high);
                vst1q_u8(
                    outputs[0][16 * half..].as_mut_ptr(),
                    vreinterpretq_u8_u32(left),
                );
                vst1q_u8(
                    outputs[1][16 * half..].as_mut_ptr(),
                    vreinterpretq_u8_u32(right),
                );
            }
            outputs
        }
    }
}

impl Dup {
    /// Exclusive-or with `other` and rotate each 64-bit lane right by `R`
    /// bits, which rotates both duplicated 32-bit copies right by `R`.
    #[inline(always)]
    unsafe fn xar<const R: i32>(self, other: Self) -> Self {
        // SAFETY: The caller establishes the SHA-3 extension.
        unsafe {
            Self(vreinterpretq_u32_u64(vxarq_u64::<R>(
                vreinterpretq_u64_u32(self.0),
                vreinterpretq_u64_u32(other.0),
            )))
        }
    }
}

/// Hash four equal-length messages, one per NEON lane.
///
/// # Safety
///
/// The caller must establish NEON availability.
#[target_feature(enable = "neon")]
unsafe fn hash_x4(inputs: [&[u8]; LANES]) -> [[u8; OUT_LEN]; LANES] {
    // SAFETY: NEON is enabled for this function.
    unsafe { super::hash::<uint32x4_t, LANES>(inputs) }
}

/// Hash eight equal-length messages, two NEON vectors per word.
///
/// # Safety
///
/// The caller must establish NEON availability.
#[target_feature(enable = "neon")]
unsafe fn hash_x8(inputs: [&[u8]; 2 * LANES]) -> [[u8; OUT_LEN]; 2 * LANES] {
    // SAFETY: NEON is enabled for this function.
    unsafe { super::hash::<Dual<uint32x4_t>, { 2 * LANES }>(inputs) }
}

/// Hash four equal-length messages with SVE2 `XAR` rotations.
///
/// # Safety
///
/// The caller must establish SVE2 availability.
#[target_feature(enable = "neon")]
unsafe fn hash_x4_xar(inputs: [&[u8]; LANES]) -> [[u8; OUT_LEN]; LANES] {
    // SAFETY: NEON is enabled for this function, and the caller establishes
    // SVE2.
    unsafe { super::hash::<Xar, LANES>(inputs) }
}

/// Hash eight equal-length messages with SVE2 `XAR` for three of the four
/// rotations.
///
/// # Safety
///
/// The caller must establish SVE2 availability.
#[target_feature(enable = "neon")]
unsafe fn hash_x8_xar(inputs: [&[u8]; 2 * LANES]) -> [[u8; OUT_LEN]; 2 * LANES] {
    // SAFETY: NEON is enabled for this function, and the caller establishes
    // SVE2.
    unsafe { super::hash::<Dual<Hybrid>, { 2 * LANES }>(inputs) }
}

/// Hash two equal-length messages with duplicated words and SHA-3 `XAR`
/// rotations.
///
/// # Safety
///
/// The caller must establish NEON and SHA-3 extension availability.
#[target_feature(enable = "neon,sha3")]
unsafe fn hash_x2_dup(inputs: [&[u8]; 2]) -> [[u8; OUT_LEN]; 2] {
    // SAFETY: NEON and the SHA-3 extension are enabled for this function.
    unsafe { super::hash::<Dup, 2>(inputs) }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        /// Return whether NEON is available.
        #[inline]
        fn supported() -> bool {
            std::arch::is_aarch64_feature_detected!("neon")
        }

        /// Return whether SVE2 is available.
        #[inline]
        fn supports_sve2() -> bool {
            std::arch::is_aarch64_feature_detected!("sve2")
        }

        /// Return whether the SHA-3 extension is available.
        #[inline]
        fn supports_sha3() -> bool {
            std::arch::is_aarch64_feature_detected!("sha3")
        }
    } else {
        /// Return whether NEON is statically enabled.
        const fn supported() -> bool {
            cfg!(target_feature = "neon")
        }

        /// Return whether SVE2 is statically enabled.
        const fn supports_sve2() -> bool {
            cfg!(target_feature = "sve2")
        }

        /// Return whether the SHA-3 extension is statically enabled.
        const fn supports_sha3() -> bool {
            cfg!(target_feature = "sha3")
        }
    }
}

/// Hash four equal-length messages with the fastest four-lane kernel.
///
/// # Safety
///
/// The caller must establish NEON availability.
#[inline]
unsafe fn hash_quad(inputs: [&[u8]; LANES], sve2: bool) -> [[u8; OUT_LEN]; LANES] {
    if sve2 {
        // SAFETY: SVE2 availability was established by the caller.
        unsafe { hash_x4_xar(inputs) }
    } else {
        // SAFETY: The caller establishes NEON.
        unsafe { hash_x4(inputs) }
    }
}

/// Hash two equal-length messages, with duplicated words when the SHA-3
/// extension is available, and otherwise with two interleaved scalar lanes.
pub(super) fn hash_pair(inputs: [&[u8]; 2]) -> [[u8; OUT_LEN]; 2] {
    if supported() && supports_sha3() {
        // SAFETY: NEON and SHA-3 extension availability were established
        // above.
        return unsafe { hash_x2_dup(inputs) };
    }
    // SAFETY: The portable words require no target features.
    unsafe { super::hash::<[u32; 2], 2>(inputs) }
}

/// Chaining values of `L` full chunks of one message with NEON words `V`.
///
/// # Safety
///
/// The caller must establish the target features `V` requires beyond NEON.
#[target_feature(enable = "neon")]
unsafe fn chunks_neon<V: Words<L>, const L: usize>(
    inputs: [&[u8]; L],
    first: u64,
) -> [[u8; OUT_LEN]; L] {
    // SAFETY: NEON is enabled for this function, and the caller establishes
    // the rest.
    unsafe { super::chunks::<V, L>(inputs, first) }
}

/// Non-root parent chaining values with NEON words `V`.
///
/// # Safety
///
/// The caller must establish the target features `V` requires beyond NEON.
#[target_feature(enable = "neon")]
unsafe fn parents_neon<V: Words<L>, const L: usize>(
    children: [&[u8; BLOCK_LEN]; L],
) -> [[u8; OUT_LEN]; L] {
    // SAFETY: NEON is enabled for this function, and the caller establishes
    // the rest.
    unsafe { super::parents::<V, L>(children) }
}

/// Chaining values of two full chunks of one message with duplicated words.
///
/// # Safety
///
/// The caller must establish NEON and SHA-3 extension availability.
#[target_feature(enable = "neon,sha3")]
unsafe fn chunks_dup(inputs: [&[u8]; 2], first: u64) -> [[u8; OUT_LEN]; 2] {
    // SAFETY: NEON and the SHA-3 extension are enabled for this function.
    unsafe { super::chunks::<Dup, 2>(inputs, first) }
}

/// Two non-root parent chaining values with duplicated words.
///
/// # Safety
///
/// The caller must establish NEON and SHA-3 extension availability.
#[target_feature(enable = "neon,sha3")]
unsafe fn parents_dup(children: [&[u8; BLOCK_LEN]; 2]) -> [[u8; OUT_LEN]; 2] {
    // SAFETY: NEON and the SHA-3 extension are enabled for this function.
    unsafe { super::parents::<Dup, 2>(children) }
}

/// Available NEON extensions.
#[derive(Clone, Copy)]
struct Features {
    sve2: bool,
    sha3: bool,
}

/// Chaining values of `active` (two to eight) full chunks of one message,
/// where lane `i` holds chunk `first + i`. Spare lanes repeat the first chunk.
///
/// # Safety
///
/// The caller must establish NEON availability.
unsafe fn chunk_cvs(
    inputs: [&[u8]; 2 * LANES],
    active: usize,
    first: u64,
    features: Features,
) -> [[u8; OUT_LEN]; 2 * LANES] {
    // SAFETY: The caller establishes NEON, and each extension is used only
    // when detected.
    unsafe {
        if active > LANES {
            if features.sve2 {
                return chunks_neon::<Dual<Hybrid>, { 2 * LANES }>(inputs, first);
            }
            return chunks_neon::<Dual<uint32x4_t>, { 2 * LANES }>(inputs, first);
        }
        let mut outputs = [[0u8; OUT_LEN]; 2 * LANES];
        if active == 2 && features.sha3 {
            outputs[..2].copy_from_slice(&chunks_dup([inputs[0], inputs[1]], first));
            return outputs;
        }
        let quad = [inputs[0], inputs[1], inputs[2], inputs[3]];
        let quad = if features.sve2 {
            chunks_neon::<Xar, LANES>(quad, first)
        } else {
            chunks_neon::<uint32x4_t, LANES>(quad, first)
        };
        outputs[..LANES].copy_from_slice(&quad);
        outputs
    }
}

/// Non-root parent chaining values of `active` (two to eight) child pairs.
/// Spare lanes repeat the first pair.
///
/// # Safety
///
/// The caller must establish NEON availability.
unsafe fn parent_cvs(
    children: [&[u8; BLOCK_LEN]; 2 * LANES],
    active: usize,
    features: Features,
) -> [[u8; OUT_LEN]; 2 * LANES] {
    // SAFETY: The caller establishes NEON, and each extension is used only
    // when detected.
    unsafe {
        if active > LANES {
            if features.sve2 {
                return parents_neon::<Dual<Hybrid>, { 2 * LANES }>(children);
            }
            return parents_neon::<Dual<uint32x4_t>, { 2 * LANES }>(children);
        }
        let mut outputs = [[0u8; OUT_LEN]; 2 * LANES];
        if active == 2 && features.sha3 {
            outputs[..2].copy_from_slice(&parents_dup([children[0], children[1]]));
            return outputs;
        }
        let quad = [children[0], children[1], children[2], children[3]];
        let quad = if features.sve2 {
            parents_neon::<Xar, LANES>(quad)
        } else {
            parents_neon::<uint32x4_t, LANES>(quad)
        };
        outputs[..LANES].copy_from_slice(&quad);
        outputs
    }
}

/// Reduce `input`, which starts at chunk `first` of its message and spans at
/// least two full chunks, to at most `target` (one or two) non-root chaining
/// values of its BLAKE3 subtree.
///
/// Full chunks are hashed in lanes, a partial final chunk alone. Then each
/// level merges adjacent pairs in lanes, and an odd last value moves up
/// unchanged, which builds BLAKE3's left-balanced tree.
///
/// # Safety
///
/// The caller must establish NEON availability.
unsafe fn reduce(input: &[u8], first: u64, target: usize) -> Vec<ChainingValue> {
    let features = Features {
        sve2: supports_sve2(),
        sha3: supports_sha3(),
    };
    let full = input.len() / CHUNK_LEN;
    let mut cvs: Vec<ChainingValue> = Vec::with_capacity(full + 1);
    for (group, span) in input[..full * CHUNK_LEN]
        .chunks(2 * LANES * CHUNK_LEN)
        .enumerate()
    {
        let active = span.len() / CHUNK_LEN;
        let first = first + (group * 2 * LANES) as u64;
        if active == 1 {
            let mut hasher = blake3::Hasher::new();
            hasher.set_input_offset(first * CHUNK_LEN as u64);
            hasher.update(span);
            cvs.push(hasher.finalize_non_root());
            continue;
        }
        let mut inputs = [&span[..CHUNK_LEN]; 2 * LANES];
        for (lane, chunk) in inputs.iter_mut().zip(span.chunks(CHUNK_LEN)) {
            *lane = chunk;
        }
        // SAFETY: The caller establishes NEON.
        let outputs = unsafe { chunk_cvs(inputs, active, first, features) };
        cvs.extend_from_slice(&outputs[..active]);
    }
    if full * CHUNK_LEN < input.len() {
        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset((first + full as u64) * CHUNK_LEN as u64);
        hasher.update(&input[full * CHUNK_LEN..]);
        cvs.push(hasher.finalize_non_root());
    }

    while cvs.len() > target {
        let mut next = Vec::with_capacity(cvs.len().div_ceil(2));
        let (pairs, rest) = cvs.as_chunks::<2>();
        for group in pairs.chunks(2 * LANES) {
            if let [[left, right]] = group {
                next.push(merge_subtrees_non_root(left, right, Mode::Hash));
                continue;
            }
            let mut children = [[0u8; BLOCK_LEN]; 2 * LANES];
            for (child, [left, right]) in children.iter_mut().zip(group) {
                child[..OUT_LEN].copy_from_slice(left);
                child[OUT_LEN..].copy_from_slice(right);
            }
            // SAFETY: The caller establishes NEON.
            let outputs = unsafe { parent_cvs(children.each_ref(), group.len(), features) };
            next.extend_from_slice(&outputs[..group.len()]);
        }
        next.extend_from_slice(rest);
        cvs = next;
    }
    cvs
}

/// Hash one message of at least two full chunks.
///
/// Returns `None` when NEON is unavailable.
pub(in crate::blake3) fn hash_large(input: &[u8]) -> Option<[u8; OUT_LEN]> {
    assert!(input.len() >= 2 * CHUNK_LEN, "message spans two chunks");
    if !supported() {
        return None;
    }
    // SAFETY: NEON availability was established above.
    let cvs = unsafe { reduce(input, 0, 2) };
    Some(*merge_subtrees_root(&cvs[0], &cvs[1], Mode::Hash).as_bytes())
}

/// Chaining value of the non-root subtree `input`, which starts at chunk
/// `first` of its message and spans at least two full chunks.
///
/// Returns `None` when NEON is unavailable.
pub(in crate::blake3) fn subtree(input: &[u8], first: u64) -> Option<ChainingValue> {
    assert!(input.len() >= 2 * CHUNK_LEN, "subtree spans two chunks");
    if !supported() {
        return None;
    }
    // SAFETY: NEON availability was established above.
    let cvs = unsafe { reduce(input, first, 1) };
    Some(cvs[0])
}

/// Hash independent messages in batches of eight, hashing partial batches of
/// at most four messages with narrower kernels.
pub(super) fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Option<Vec<Digest>> {
    if !supported() {
        return None;
    }
    Some(batch(messages, MINIMUM, |inputs, active| {
        if active > LANES {
            if supports_sve2() {
                // SAFETY: NEON and SVE2 availability were established above.
                return unsafe { hash_x8_xar(inputs) };
            }
            // SAFETY: NEON availability was established above.
            return unsafe { hash_x8(inputs) };
        }

        // Spare lanes repeat the first input, so a narrower kernel takes the
        // leading lanes and leaves the rest unused.
        let mut outputs = [[0u8; OUT_LEN]; 2 * LANES];
        if active == 2 && supports_sha3() {
            // SAFETY: NEON and SHA-3 extension availability were established
            // above.
            let pair = unsafe { hash_x2_dup([inputs[0], inputs[1]]) };
            outputs[..2].copy_from_slice(&pair);
            return outputs;
        }
        let quad = [inputs[0], inputs[1], inputs[2], inputs[3]];
        // SAFETY: NEON availability was established above.
        outputs[..LANES].copy_from_slice(&unsafe { hash_quad(quad, supports_sve2()) });
        outputs
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lanes_match_reference() {
        assert!(supported());

        // SAFETY: NEON availability was asserted above.
        super::super::tests::check_lanes::<LANES>(|inputs| unsafe { hash_x4(inputs) });
        // SAFETY: NEON availability was asserted above.
        super::super::tests::check_lanes::<{ 2 * LANES }>(|inputs| unsafe { hash_x8(inputs) });
    }

    #[test]
    fn test_xar_lanes_match_reference() {
        if !std::arch::is_aarch64_feature_detected!("sve2") {
            return;
        }

        // SAFETY: SVE2 availability was checked above.
        super::super::tests::check_lanes::<LANES>(|inputs| unsafe { hash_x4_xar(inputs) });
        // SAFETY: SVE2 availability was checked above.
        super::super::tests::check_lanes::<{ 2 * LANES }>(|inputs| unsafe { hash_x8_xar(inputs) });
    }

    #[test]
    fn test_dup_lanes_match_reference() {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            return;
        }

        // SAFETY: SHA-3 extension availability was checked above.
        super::super::tests::check_lanes::<2>(|inputs| unsafe { hash_x2_dup(inputs) });
    }

    /// Check subtree chaining values against the reference at subtree-aligned
    /// first chunks, with full groups of eight chunks, narrower tails, a
    /// single trailing chunk, and partial final chunks.
    #[test]
    fn test_subtree_matches_reference() {
        let data: Vec<u8> = (0..40 * CHUNK_LEN as u32)
            .map(|i| (i.wrapping_mul(0x0100_0193) >> 11) as u8)
            .collect();
        for chunks in [2, 3, 4, 5, 8, 9, 10, 16, 17, 32] {
            for extra in [0, 1, CHUNK_LEN - 1] {
                let len = chunks * CHUNK_LEN + extra;
                // A subtree starting at chunk `first` spans at most the
                // largest power of two dividing `first`, so these starts
                // admit every tested length.
                for first in [0u64, 64, 192] {
                    let input = &data[..len];
                    let mut hasher = blake3::Hasher::new();
                    hasher.set_input_offset(first * CHUNK_LEN as u64);
                    hasher.update(input);
                    let expected = hasher.finalize_non_root();
                    assert_eq!(
                        subtree(input, first),
                        Some(expected),
                        "len={len} first={first}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_xar_encoding() {
        // `XAR Z0.S, Z0.S, Z0.S, #16` and `#7`, as LLVM's assembler encodes
        // them.
        assert_eq!(xar_encoding(16), 0x0470_3400);
        assert_eq!(xar_encoding(7), 0x0479_3400);
    }
}
