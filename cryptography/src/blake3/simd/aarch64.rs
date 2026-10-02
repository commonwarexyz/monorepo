//! NEON kernels.

#[cfg(doc)]
use super::batch;
use super::{Digest, Words};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blake3::{BLOCK_LEN, CHUNK_LEN, OUT_LEN};
use core::arch::aarch64::*;
#[cfg(not(miri))]
use core::arch::asm;

/// Messages per NEON vector.
const LANES: usize = 4;

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

/// Rotate each 32-bit lane right by `R` bits with scalar rotates.
#[cfg(miri)]
#[inline(always)]
fn rotate_words<const R: u32>(x: uint32x4_t) -> uint32x4_t {
    // SAFETY: Both types are 16 bytes, and every bit pattern is valid for both.
    let mut words: [u32; 4] = unsafe { core::mem::transmute(x) };
    for word in &mut words {
        *word = word.rotate_right(R);
    }

    // SAFETY: Both types are 16 bytes, and every bit pattern is valid for both.
    unsafe { core::mem::transmute(words) }
}

/// Rotate each 32-bit lane right by `R` bits (`L` must be `32 - R`) with a
/// shift left and a shift right and insert.
///
/// The insert is written in assembly because LLVM rewrites the intrinsic
/// form of this idiom as a shift left and an accumulating shift right, which
/// has a longer dependency chain on Neoverse V2.
#[inline(always)]
unsafe fn rotate<const R: u32, const L: i32>(x: uint32x4_t) -> uint32x4_t {
    cfg_if::cfg_if! {
        if #[cfg(miri)] {
            // Miri does not interpret inline assembly.
            rotate_words::<R>(x)
        } else {
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

/// Borrow `N` bytes of `bytes` at `offset`.
///
/// # Panics
///
/// Panics if `bytes` is shorter than `offset + N` bytes.
#[inline(always)]
fn at<const N: usize>(bytes: &[u8], offset: usize) -> &[u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("range spans N bytes")
}

/// Load 16 bytes as four little-endian words.
#[inline(always)]
unsafe fn row(bytes: &[u8; 16]) -> uint32x4_t {
    // SAFETY: The caller establishes NEON, and the load reads the 16 bytes.
    unsafe { vreinterpretq_u32_u8(vld1q_u8(bytes.as_ptr())) }
}

/// Load and transpose 16 bytes at `offset` of each block.
///
/// # Panics
///
/// Panics if `offset` exceeds `BLOCK_LEN - 16`.
#[inline(always)]
unsafe fn quarter(blocks: [&[u8; BLOCK_LEN]; LANES], offset: usize) -> [uint32x4_t; 4] {
    // SAFETY: The caller establishes NEON.
    unsafe {
        transpose([
            row(at(blocks[0], offset)),
            row(at(blocks[1], offset)),
            row(at(blocks[2], offset)),
            row(at(blocks[3], offset)),
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
        // SAFETY: The caller establishes NEON.
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
    unsafe fn load_partial(inputs: [&[u8]; LANES], start: usize, len: usize) -> [Self; 16] {
        // SAFETY: The caller establishes NEON.
        unsafe { super::pad(inputs, start, len) }
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
#[cfg(any(not(miri), test))]
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
unsafe fn xar<const R: u32>(dn: uint32x4_t, m: uint32x4_t) -> uint32x4_t {
    cfg_if::cfg_if! {
        if #[cfg(miri)] {
            // Miri does not interpret inline assembly.
            // SAFETY: The caller establishes SVE2, which implies NEON.
            rotate_words::<R>(unsafe { veorq_u32(dn, m) })
        } else {
            let mut dn = dn;

            // SAFETY: The caller establishes SVE2. The assembly only reads and
            // writes the two vector registers, and `XAR` leaves the
            // destination's high bits zero when both sources have zero high
            // bits.
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
    }
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
        // Explicit word construction keeps constant tail words visible to compression.
        // SAFETY: The caller establishes NEON.
        unsafe {
            let [
                m0,
                m1,
                m2,
                m3,
                m4,
                m5,
                m6,
                m7,
                m8,
                m9,
                m10,
                m11,
                m12,
                m13,
                m14,
                m15,
            ] = <uint32x4_t as Words<LANES>>::load(blocks);
            [
                Self(m0),
                Self(m1),
                Self(m2),
                Self(m3),
                Self(m4),
                Self(m5),
                Self(m6),
                Self(m7),
                Self(m8),
                Self(m9),
                Self(m10),
                Self(m11),
                Self(m12),
                Self(m13),
                Self(m14),
                Self(m15),
            ]
        }
    }

    #[inline(always)]
    unsafe fn load_partial(inputs: [&[u8]; LANES], start: usize, len: usize) -> [Self; 16] {
        // SAFETY: The caller establishes NEON.
        unsafe { super::pad(inputs, start, len) }
    }

    #[inline(always)]
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; LANES] {
        // SAFETY: The caller establishes NEON.
        unsafe { <uint32x4_t as Words<LANES>>::store(words.map(|word| word.0)) }
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

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        /// Return whether NEON is available.
        #[inline]
        pub(super) fn supported() -> bool {
            std::arch::is_aarch64_feature_detected!("neon")
        }

        /// Return whether SVE2 is available.
        #[inline]
        fn supports_sve2() -> bool {
            std::arch::is_aarch64_feature_detected!("sve2")
        }
    } else {
        /// Return whether NEON is statically enabled.
        pub(super) const fn supported() -> bool {
            cfg!(target_feature = "neon")
        }

        /// Return whether SVE2 is statically enabled.
        const fn supports_sve2() -> bool {
            cfg!(target_feature = "sve2")
        }
    }
}

/// Hash four equal-length messages with the fastest four-lane kernel.
///
/// # Safety
///
/// The caller must establish NEON availability and SVE2 availability when
/// `sve2` is true.
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

/// Bytes in an MMR node message: a position followed by two digests.
const MMR_LEN: usize = 8 + 2 * OUT_LEN;

/// Hash four [`MMR_LEN`]-byte messages with SVE2 `XAR` rotations and a length
/// fixed at compile time.
///
/// Each message is a full block followed by an eight-byte final block, so the
/// final compression reads its fourteen zero padding words as constants.
///
/// # Safety
///
/// The caller must establish NEON and SVE2 availability.
#[inline(never)]
#[target_feature(enable = "neon")]
unsafe fn hash_quad_mmr(inputs: [&[u8; MMR_LEN]; LANES]) -> [[u8; OUT_LEN]; LANES] {
    // SAFETY: The caller establishes NEON and SVE2. Each input contains one
    // full block followed by an eight-byte tail.
    unsafe {
        let blocks = inputs.map(|input| {
            input[..BLOCK_LEN]
                .try_into()
                .expect("block is BLOCK_LEN bytes")
        });
        let mut cv = super::iv::<Xar, LANES>();
        let message = Xar::load(blocks);
        super::compress(&mut cv, &message, 0, BLOCK_LEN, super::CHUNK_START);
        let len = MMR_LEN - BLOCK_LEN;
        let tail = Xar::load_partial(inputs.map(|input| &input[..]), BLOCK_LEN, len);
        super::compress(&mut cv, &tail, 0, len, super::CHUNK_END | super::ROOT);
        Xar::store(cv)
    }
}

/// Hash three or four equal-length messages of at most one chunk with the
/// four-lane kernel, without the run and packing checks of [`batch`]. With
/// SVE2, messages of [`MMR_LEN`] bytes use [`hash_quad_mmr`].
///
/// # Safety
///
/// The caller must establish NEON availability. If `sve2` is true, it must also
/// establish SVE2 availability.
#[inline(never)]
#[target_feature(enable = "neon")]
unsafe fn hash_small<M: AsRef<[u8]>>(messages: &[M], sve2: bool) -> Option<Vec<Digest>> {
    let inputs = match messages {
        [a, b, c] => {
            let first = a.as_ref();
            [first, b.as_ref(), c.as_ref(), first]
        }
        [a, b, c, d] => [a.as_ref(), b.as_ref(), c.as_ref(), d.as_ref()],
        _ => return None,
    };
    let len = inputs[0].len();
    if len > CHUNK_LEN || inputs.iter().any(|input| input.len() != len) {
        return None;
    }

    // SAFETY: NEON is enabled, the caller established the optional SVE2
    // feature, and every captured lane has the same validated length.
    let outputs = unsafe {
        if sve2 && len == MMR_LEN {
            hash_quad_mmr(inputs.map(|input| input.try_into().expect("input is MMR_LEN bytes")))
        } else {
            hash_quad(inputs, sve2)
        }
    };
    Some(
        outputs
            .into_iter()
            .take(messages.len())
            .map(Digest)
            .collect(),
    )
}

/// Hash independent messages with NEON batch kernels.
pub(super) fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Option<Vec<Digest>> {
    if !supported() {
        return None;
    }
    let sve2 = supports_sve2();
    if matches!(messages.len(), 3 | 4) {
        // SAFETY: NEON availability was established above, and the feature
        // snapshot records whether the four-lane SVE2 kernel is available.
        if let Some(digests) = unsafe { hash_small(messages, sve2) } {
            return Some(digests);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake3::simd::tests::check_lanes;

    #[test]
    fn test_lanes_match_reference() {
        assert!(supported());

        // SAFETY: NEON availability was asserted above.
        check_lanes::<LANES>(|inputs| unsafe { hash_x4(inputs) });
    }

    #[test]
    fn test_xar_lanes_match_reference() {
        if !std::arch::is_aarch64_feature_detected!("sve2") {
            return;
        }

        // SAFETY: SVE2 availability was checked above.
        check_lanes::<LANES>(|inputs| unsafe { hash_x4_xar(inputs) });
    }

    #[test]
    fn test_xar_encoding() {
        // `XAR Z0.S, Z0.S, Z0.S, #16` and `#7`, as LLVM's assembler encodes
        // them.
        assert_eq!(xar_encoding(16), 0x0470_3400);
        assert_eq!(xar_encoding(7), 0x0479_3400);
    }
}
