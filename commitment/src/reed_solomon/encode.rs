//! Reed-Solomon encoding routines.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{fft, short_from_long_twiddles, ReedSolomon};
use crate::field::BinaryFieldElement;

/// Encode a message using Reed-Solomon
pub fn encode<F: BinaryFieldElement + 'static>(rs: &ReedSolomon<F>, message: &[F]) -> Vec<F> {
    let mut encoded = vec![F::zero(); rs.block_length()];
    encoded[..message.len()].copy_from_slice(message);

    encode_in_place(rs, &mut encoded);
    encoded
}

/// Encode in-place (systematic encoding)
pub fn encode_in_place<F: BinaryFieldElement + 'static>(rs: &ReedSolomon<F>, data: &mut [F]) {
    encode_in_place_with_parallel(rs, data, true)
}

/// Encode in-place with configurable parallelization
pub fn encode_in_place_with_parallel<F: BinaryFieldElement + 'static>(
    rs: &ReedSolomon<F>,
    data: &mut [F],
    parallel: bool,
) {
    use crate::field::BinaryElem32;
    use core::any::TypeId;

    // Fast path for BinaryElem32 using SIMD
    if TypeId::of::<F>() == TypeId::of::<BinaryElem32>() {
        // SAFETY: We just verified via TypeId that F is BinaryElem32. Both types
        // have the same size and alignment, so from_raw_parts_mut/from_raw_parts
        // produce valid slices. The lifetime and length are preserved from the
        // originating slices.
        let data_gf32 = unsafe {
            core::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut BinaryElem32, data.len())
        };
        // SAFETY: Same reasoning as above - F is BinaryElem32, so the twiddles
        // slice can be safely reinterpreted.
        let twiddles_gf32 = unsafe {
            core::slice::from_raw_parts(
                rs.twiddles.as_ptr() as *const BinaryElem32,
                rs.twiddles.len(),
            )
        };

        let message_len = rs.message_length();
        let short_twiddles =
            short_from_long_twiddles(twiddles_gf32, rs.log_block_length, rs.log_message_length);

        super::fft_gf32::ifft_gf32(&mut data_gf32[..message_len], &short_twiddles);
        super::fft_gf32::fft_gf32(data_gf32, twiddles_gf32, parallel);
        return;
    }

    // Generic fallback
    let message_len = rs.message_length();
    let short_twiddles =
        short_from_long_twiddles(&rs.twiddles, rs.log_block_length, rs.log_message_length);
    fft::ifft(&mut data[..message_len], &short_twiddles);
    fft::fft(data, &rs.twiddles, parallel);
}

/// Non-systematic encoding for Ligero
pub fn encode_non_systematic<F: BinaryFieldElement + 'static>(
    rs: &ReedSolomon<F>,
    data: &mut [F],
) {
    use crate::field::BinaryElem32;
    use core::any::TypeId;

    assert_eq!(data.len(), rs.block_length());

    // Scale by pi polynomials before FFT
    let message_len = rs.message_length();
    for i in 0..message_len {
        data[i] = data[i].mul(&rs.pis[i]);
    }

    // Fast path for BinaryElem32 using SIMD
    if TypeId::of::<F>() == TypeId::of::<BinaryElem32>() {
        // SAFETY: We just verified via TypeId that F is BinaryElem32. Both types
        // have the same size and alignment, so from_raw_parts_mut/from_raw_parts
        // produce valid slices. The lifetime and length are preserved.
        let data_gf32 = unsafe {
            core::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut BinaryElem32, data.len())
        };
        // SAFETY: Same reasoning - F is BinaryElem32, twiddles reinterpretation is sound.
        let twiddles_gf32 = unsafe {
            core::slice::from_raw_parts(
                rs.twiddles.as_ptr() as *const BinaryElem32,
                rs.twiddles.len(),
            )
        };
        super::fft_gf32::fft_gf32(data_gf32, twiddles_gf32, true);
        return;
    }

    // Generic fallback
    fft::fft(data, &rs.twiddles, true);
}
