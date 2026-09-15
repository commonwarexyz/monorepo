use super::K;
use crate::sha256::{DIGEST_LENGTH, IV};
use core::arch::asm;

const LANES: usize = 16;
const BLOCK_LENGTH: usize = 64;
const DIGEST_WORDS: usize = 8;

#[repr(align(64))]
struct Align64<T>(T);

type StateWords = [[u32; LANES]; DIGEST_WORDS];

static BYTE_SWAP_MASK: Align64<[u8; 32]> = Align64([
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15,
    14, 13, 12,
]);

/// Hash exactly 16 equal-length contiguous messages in independent SIMD lanes.
///
/// Input lane `i` maps to output lane `i`.
///
/// # Safety
///
/// The caller must establish AVX512F, AVX512BW, and AVX512VL availability and
/// ensure every input has the same length.
#[target_feature(enable = "avx512f,avx512bw,avx512vl")]
pub(in crate::sha256::simd) unsafe fn hash_x16_equal(
    inputs: [&[u8]; LANES],
) -> [[u8; DIGEST_LENGTH]; LANES] {
    let len = inputs[0].len();
    assert!(
        inputs[1..].iter().all(|input| input.len() == len),
        "SHA-256 x16 inputs must have equal lengths"
    );

    let mut state = Align64([[0u32; LANES]; DIGEST_WORDS]);
    for (word, lanes) in state.0.iter_mut().enumerate() {
        lanes.fill(IV[word]);
    }

    let full_blocks = len / BLOCK_LENGTH;
    if full_blocks != 0 {
        let mut data_pointers: [*const u8; LANES] =
            core::array::from_fn(|lane| inputs[lane].as_ptr());

        // SAFETY: Equal lengths give every pointer `full_blocks` readable
        // blocks. The function target features satisfy the compressor.
        unsafe { compress_blocks(&mut state, &mut data_pointers, full_blocks) };
    }

    let full_len = full_blocks * BLOCK_LENGTH;
    let remainder = len - full_len;
    let padding_blocks = if remainder < 56 { 1 } else { 2 };
    let padding_len = padding_blocks * BLOCK_LENGTH;
    let mut padding = [[0u8; 2 * BLOCK_LENGTH]; LANES];
    let bit_len = (len as u64).wrapping_mul(8).to_be_bytes();

    for lane in 0..LANES {
        padding[lane][..remainder].copy_from_slice(&inputs[lane][full_len..]);
        padding[lane][remainder] = 0x80;
        padding[lane][padding_len - 8..padding_len].copy_from_slice(&bit_len);
    }

    let mut padding_pointers: [*const u8; LANES] =
        core::array::from_fn(|lane| padding[lane].as_ptr());

    // SAFETY: Every padding lane has 128 initialized bytes, and
    // `padding_blocks` is one or two. The function establishes all features.
    unsafe { compress_blocks(&mut state, &mut padding_pointers, padding_blocks) };

    let mut output = [[0u8; DIGEST_LENGTH]; LANES];
    for (lane, digest) in output.iter_mut().enumerate() {
        for word in 0..DIGEST_WORDS {
            let offset = word * 4;
            digest[offset..offset + 4].copy_from_slice(&state.0[word][lane].to_be_bytes());
        }
    }
    output
}

#[target_feature(enable = "avx512f,avx512bw,avx512vl")]
unsafe fn compress_blocks(
    state: &mut Align64<StateWords>,
    data_pointers: &mut [*const u8; LANES],
    blocks: usize,
) {
    // SAFETY: Each pointer addresses at least `blocks * 64` readable bytes.
    // State, constants, and mask expose 512, 256, and 32 initialized bytes.
    // The assembly mutates only state and the private pointer table. It has no
    // stack access or calls. Every written GPR and SIMD register is declared;
    // flags and memory remain conservatively clobbered.
    unsafe {
        asm!(
            include_str!("sha256_x16.asm"),
            state = in(reg) state.0.as_mut_ptr(),
            data = in(reg) data_pointers.as_mut_ptr(),
            blocks = inout(reg) blocks => _,
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            out("rax") _, out("r8") _, out("r9") _,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            out("xmm16") _, out("xmm17") _, out("xmm18") _, out("xmm19") _,
            out("xmm20") _, out("xmm21") _, out("xmm22") _, out("xmm23") _,
            out("xmm24") _, out("xmm25") _, out("xmm26") _, out("xmm27") _,
            out("xmm28") _, out("xmm29") _, out("xmm30") _, out("xmm31") _,
            options(nostack),
        );
    }
}
