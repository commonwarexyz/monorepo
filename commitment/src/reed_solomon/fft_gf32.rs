//! Specialized SIMD FFT for BinaryElem32.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryElem32;

/// FFT butterfly using SIMD for GF(2^32)
#[inline(always)]
fn fft_mul_simd(v: &mut [BinaryElem32], lambda: BinaryElem32) {
    let (u, w) = v.split_at_mut(v.len() / 2);
    // Use the generic fft_butterfly_gf32 which internally dispatches to the best implementation
    crate::field::simd::fft_butterfly_gf32(u, w, lambda);
}

/// Monomorphic recursive FFT for GF(2^32) with SIMD
fn fft_twiddles_gf32(v: &mut [BinaryElem32], twiddles: &[BinaryElem32], idx: usize) {
    if v.len() == 1 {
        return;
    }

    fft_mul_simd(v, twiddles[idx - 1]);

    let mid = v.len() / 2;
    let (u, w) = v.split_at_mut(mid);

    fft_twiddles_gf32(u, twiddles, 2 * idx);
    fft_twiddles_gf32(w, twiddles, 2 * idx + 1);
}

/// Parallel monomorphic FFT for GF(2^32) with SIMD
#[cfg(feature = "parallel")]
fn fft_twiddles_gf32_parallel(
    v: &mut [BinaryElem32],
    twiddles: &[BinaryElem32],
    idx: usize,
    thread_depth: usize,
) {
    const MIN_PARALLEL_SIZE: usize = 16384;

    let len = v.len();
    if len == 1 {
        return;
    }

    fft_mul_simd(v, twiddles[idx - 1]);

    let mid = len / 2;
    let (u, w) = v.split_at_mut(mid);

    if thread_depth > 0 && len >= MIN_PARALLEL_SIZE {
        rayon::join(
            || fft_twiddles_gf32_parallel(u, twiddles, 2 * idx, thread_depth - 1),
            || fft_twiddles_gf32_parallel(w, twiddles, 2 * idx + 1, thread_depth - 1),
        );
    } else {
        fft_twiddles_gf32(u, twiddles, 2 * idx);
        fft_twiddles_gf32(w, twiddles, 2 * idx + 1);
    }
}

/// Optimized FFT for GF(2^32)
pub fn fft_gf32(v: &mut [BinaryElem32], twiddles: &[BinaryElem32], parallel: bool) {
    if v.len() == 1 {
        return;
    }

    #[cfg(feature = "parallel")]
    {
        if parallel {
            let thread_count = rayon::current_num_threads();
            // Limit depth to reduce task overhead - only create ~2x threads worth of tasks
            let thread_depth = (thread_count as f64).log2().ceil() as usize;
            fft_twiddles_gf32_parallel(v, twiddles, 1, thread_depth);
        } else {
            fft_twiddles_gf32(v, twiddles, 1);
        }
    }

    #[cfg(not(feature = "parallel"))]
    {
        let _ = parallel;
        fft_twiddles_gf32(v, twiddles, 1);
    }
}

/// Optimized IFFT for GF(2^32)
pub fn ifft_gf32(v: &mut [BinaryElem32], twiddles: &[BinaryElem32]) {
    let n = v.len();
    if n == 1 {
        return;
    }

    // Reverse order
    for i in 1..n {
        let rev_i = i.reverse_bits() >> (usize::BITS as usize - n.trailing_zeros() as usize);
        if i < rev_i {
            v.swap(i, rev_i);
        }
    }

    fft_gf32(v, twiddles, false);
}
