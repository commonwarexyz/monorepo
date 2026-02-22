//! GF(2^8) Reed-Solomon engine using native Rust with SIMD acceleration.
//!
//! This engine implements Reed-Solomon erasure coding over GF(2^8), supporting up
//! to 255 total shards. It uses a systematic Vandermonde encoding matrix and
//! multi-destination SIMD multiply-accumulate kernels for ISA-L-class performance.
//!
//! The encoding is systematic: original data shards pass through unchanged, and
//! recovery shards are computed as GF(2^8) linear combinations of the originals.

use super::{
    gf8_arithmetic::{inv, mul},
    gf8_simd::{gf_vect_mad, gf_vect_mad_multi},
    Engine,
};
use thiserror::Error;

/// Maximum total shards for GF(2^8): 255 distinct nonzero evaluation points.
const MAX_SHARDS: usize = 255;

/// Errors from the GF(2^8) Reed-Solomon engine.
#[derive(Error, Debug)]
pub enum Error {
    #[error("too many shards: {0} (max {MAX_SHARDS})")]
    TooManyShards(usize),
    #[error("not enough shards for recovery")]
    NotEnoughShards,
    #[error("wrong number of original shards: got {got}, expected {expected}")]
    WrongShardCount { got: usize, expected: usize },
    #[error("inconsistent shard lengths")]
    InconsistentShardLengths,
    #[error("singular matrix (should not happen with valid parameters)")]
    SingularMatrix,
}

/// GF(2^8) Reed-Solomon engine with SIMD-accelerated field arithmetic.
///
/// Supports up to 255 total shards (k + m <= 255). Uses the AES irreducible
/// polynomial (0x11B) for compatibility with hardware GFNI instructions.
#[derive(Clone, Debug)]
pub struct Gf8;

impl Engine for Gf8 {
    type Error = Error;

    const SHARD_ALIGNMENT: usize = 1;

    fn max_shards() -> usize {
        MAX_SHARDS
    }

    fn encode(k: usize, m: usize, original: &[&[u8]]) -> Result<Vec<Vec<u8>>, Self::Error> {
        let n = k + m;
        if n > MAX_SHARDS {
            return Err(Error::TooManyShards(n));
        }
        if original.len() != k {
            return Err(Error::WrongShardCount {
                got: original.len(),
                expected: k,
            });
        }
        if k == 0 {
            return Ok(vec![]);
        }

        let shard_len = original[0].len();
        for s in original.iter().skip(1) {
            if s.len() != shard_len {
                return Err(Error::InconsistentShardLengths);
            }
        }

        let enc_matrix = build_encoding_matrix(k, m)?;
        let mut recovery = vec![vec![0u8; shard_len]; m];

        // Multi-destination encode: process recovery shards in groups for cache efficiency.
        // Each pass over the original data updates multiple recovery shards simultaneously,
        // loading source data once and scattering to N outputs (ISA-L pattern).
        let group_size = 4;
        for group_start in (0..m).step_by(group_size) {
            let group_end = (group_start + group_size).min(m);
            let num_dsts = group_end - group_start;

            for j in 0..k {
                if num_dsts == 1 {
                    // Single destination: use the optimized single-dest kernel
                    let coeff = enc_matrix[group_start * k + j];
                    gf_vect_mad(&mut recovery[group_start], original[j], coeff);
                } else {
                    let coeffs: Vec<u8> = (group_start..group_end)
                        .map(|i| enc_matrix[i * k + j])
                        .collect();
                    let mut dsts: Vec<&mut [u8]> = recovery[group_start..group_end]
                        .iter_mut()
                        .map(|s| s.as_mut_slice())
                        .collect();
                    gf_vect_mad_multi(&mut dsts, original[j], &coeffs);
                }
            }
        }

        Ok(recovery)
    }

    fn decode(
        k: usize,
        m: usize,
        shard_len: usize,
        provided_original: &[(usize, &[u8])],
        provided_recovery: &[(usize, &[u8])],
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        let n = k + m;
        if n > MAX_SHARDS {
            return Err(Error::TooManyShards(n));
        }

        let total_provided = provided_original.len() + provided_recovery.len();
        if total_provided < k {
            return Err(Error::NotEnoughShards);
        }

        if k == 0 {
            return Ok(vec![]);
        }

        // Build the encoding matrix (same as used for encoding)
        let enc_matrix = build_encoding_matrix(k, m)?;

        // Select exactly k shards for reconstruction, preferring originals
        // (identity rows require no computation).
        let mut selected: Vec<(usize, &[u8])> = Vec::with_capacity(k);
        for &(idx, data) in provided_original {
            if selected.len() >= k {
                break;
            }
            selected.push((idx, data));
        }
        for &(idx, data) in provided_recovery {
            if selected.len() >= k {
                break;
            }
            // Recovery index is offset by k in the full code matrix
            selected.push((k + idx, data));
        }

        // Build the k x k submatrix from selected rows of the full code matrix.
        // The full code matrix is:
        //   rows 0..k:   identity matrix (original shards)
        //   rows k..n:   encoding matrix (recovery shards)
        let mut submatrix = vec![0u8; k * k];
        for (row, &(idx, _)) in selected.iter().enumerate() {
            if idx < k {
                // Identity row
                submatrix[row * k + idx] = 1;
            } else {
                // Encoding matrix row
                let enc_row = idx - k;
                submatrix[row * k..row * k + k]
                    .copy_from_slice(&enc_matrix[enc_row * k..enc_row * k + k]);
            }
        }

        // Invert the submatrix
        let inv_matrix = invert_matrix(&submatrix, k)?;

        // Multiply: result[j] = sum_i inv_matrix[j][i] * selected_data[i]
        let mut result = vec![vec![0u8; shard_len]; k];

        let group_size = 4;
        for group_start in (0..k).step_by(group_size) {
            let group_end = (group_start + group_size).min(k);
            let num_dsts = group_end - group_start;

            for (i, &(_, data)) in selected.iter().enumerate() {
                if num_dsts == 1 {
                    let coeff = inv_matrix[group_start * k + i];
                    gf_vect_mad(&mut result[group_start], data, coeff);
                } else {
                    let coeffs: Vec<u8> = (group_start..group_end)
                        .map(|j| inv_matrix[j * k + i])
                        .collect();
                    let mut dsts: Vec<&mut [u8]> = result[group_start..group_end]
                        .iter_mut()
                        .map(|s| s.as_mut_slice())
                        .collect();
                    gf_vect_mad_multi(&mut dsts, data, &coeffs);
                }
            }
        }

        Ok(result)
    }
}

/// Build the encoding matrix (m x k) for systematic Reed-Solomon.
///
/// The full code matrix has k identity rows on top (original shards pass through)
/// and m encoding rows on bottom (recovery shards). This function returns only
/// the bottom m rows (the encoding matrix).
///
/// Uses a Vandermonde matrix with evaluation points 1..=n, then multiplies by the
/// inverse of the top k x k submatrix to produce systematic form.
fn build_encoding_matrix(k: usize, m: usize) -> Result<Vec<u8>, Error> {
    let n = k + m;
    assert!(n <= MAX_SHARDS);

    if m == 0 {
        return Ok(vec![]);
    }

    // Build Vandermonde matrix n x k
    // V[i][j] = x_i^j where x_i = (i + 1)
    let mut vander = vec![0u8; n * k];
    for i in 0..n {
        let x = (i + 1) as u8; // evaluation points 1..=n (all distinct, nonzero)
        let mut xi: u8 = 1;
        for j in 0..k {
            vander[i * k + j] = xi;
            xi = mul(xi, x);
        }
    }

    // Extract top k x k submatrix and invert
    let top = vander[..k * k].to_vec();
    let inv_top = invert_matrix(&top, k)?;

    // Multiply bottom m rows by inverse to get systematic encoding matrix:
    // enc[i][j] = sum_l vander[k+i][l] * inv_top[l][j]
    let mut enc = vec![0u8; m * k];
    for i in 0..m {
        for j in 0..k {
            let mut sum = 0u8;
            for l in 0..k {
                sum ^= mul(vander[(k + i) * k + l], inv_top[l * k + j]);
            }
            enc[i * k + j] = sum;
        }
    }

    Ok(enc)
}

/// Invert a k x k matrix in GF(2^8) via Gaussian elimination with partial pivoting.
fn invert_matrix(matrix: &[u8], k: usize) -> Result<Vec<u8>, Error> {
    assert_eq!(matrix.len(), k * k);

    if k == 0 {
        return Ok(vec![]);
    }

    // Augment [matrix | identity]
    let stride = 2 * k;
    let mut aug = vec![0u8; k * stride];
    for i in 0..k {
        for j in 0..k {
            aug[i * stride + j] = matrix[i * k + j];
        }
        aug[i * stride + k + i] = 1;
    }

    // Forward elimination with partial pivoting
    for col in 0..k {
        // Find pivot (first nonzero entry in column)
        let mut pivot = col;
        while pivot < k && aug[pivot * stride + col] == 0 {
            pivot += 1;
        }
        if pivot >= k {
            return Err(Error::SingularMatrix);
        }

        // Swap rows
        if pivot != col {
            for j in 0..stride {
                aug.swap(col * stride + j, pivot * stride + j);
            }
        }

        // Scale pivot row to make pivot element 1
        let inv_pivot = inv(aug[col * stride + col]);
        for j in 0..stride {
            aug[col * stride + j] = mul(aug[col * stride + j], inv_pivot);
        }

        // Eliminate column in all other rows
        for i in 0..k {
            if i == col {
                continue;
            }
            let factor = aug[i * stride + col];
            if factor == 0 {
                continue;
            }
            for j in 0..stride {
                aug[i * stride + j] ^= mul(factor, aug[col * stride + j]);
            }
        }
    }

    // Extract inverse from right half
    let mut result = vec![0u8; k * k];
    for i in 0..k {
        result[i * k..i * k + k].copy_from_slice(&aug[i * stride + k..i * stride + stride]);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_inverse() {
        let k = 4;
        let mut identity = vec![0u8; k * k];
        for i in 0..k {
            identity[i * k + i] = 1;
        }
        let inv = invert_matrix(&identity, k).unwrap();
        assert_eq!(inv, identity);
    }

    #[test]
    fn test_matrix_inverse_roundtrip() {
        // A * A^-1 should be the identity
        let k = 3;
        let enc = build_encoding_matrix(k, 2).unwrap();
        // Build the full submatrix for rows [0,1,2] (identity rows) -- trivially identity
        // Test with a mixed submatrix instead: rows 0 (identity), 3 (enc row 0), 4 (enc row 1)
        let mut sub = vec![0u8; k * k];
        // Row 0: identity row 0
        sub[0] = 1;
        // Row 1: encoding row 0
        sub[k..2 * k].copy_from_slice(&enc[..k]);
        // Row 2: encoding row 1
        sub[2 * k..3 * k].copy_from_slice(&enc[k..2 * k]);

        let inv_sub = invert_matrix(&sub, k).unwrap();

        // Multiply sub * inv_sub, should get identity
        let mut product = vec![0u8; k * k];
        for i in 0..k {
            for j in 0..k {
                let mut sum = 0u8;
                for l in 0..k {
                    sum ^= mul(sub[i * k + l], inv_sub[l * k + j]);
                }
                product[i * k + j] = sum;
            }
        }

        for i in 0..k {
            for j in 0..k {
                let expected = if i == j { 1 } else { 0 };
                assert_eq!(
                    product[i * k + j],
                    expected,
                    "product[{i}][{j}] = {}, expected {expected}",
                    product[i * k + j]
                );
            }
        }
    }

    #[test]
    fn test_encode_decode_basic() {
        let k = 3;
        let m = 2;
        let data: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();

        let recovery = Gf8::encode(k, m, &refs).unwrap();
        assert_eq!(recovery.len(), m);
        assert!(recovery.iter().all(|s| s.len() == 4));

        // Decode using all originals -- should work trivially
        let orig: Vec<(usize, &[u8])> = data.iter().enumerate().map(|(i, d)| (i, d.as_slice())).collect();
        let result = Gf8::decode(k, m, 4, &orig, &[]).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_encode_decode_with_recovery() {
        let k = 3;
        let m = 3;
        let data: Vec<Vec<u8>> = vec![
            vec![10, 20, 30, 40, 50],
            vec![60, 70, 80, 90, 100],
            vec![110, 120, 130, 140, 150],
        ];
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();

        let recovery = Gf8::encode(k, m, &refs).unwrap();

        // Lose all originals, decode from recovery only
        let rec: Vec<(usize, &[u8])> = recovery.iter().enumerate().map(|(i, d)| (i, d.as_slice())).collect();
        let result = Gf8::decode(k, m, 5, &[], &rec).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_encode_decode_mixed_shards() {
        let k = 4;
        let m = 4;
        let data: Vec<Vec<u8>> = (0..k).map(|i| vec![(i * 10) as u8; 100]).collect();
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();

        let recovery = Gf8::encode(k, m, &refs).unwrap();

        // Use originals 0, 2 and recovery 1, 3
        let orig = vec![(0, data[0].as_slice()), (2, data[2].as_slice())];
        let rec = vec![(1, recovery[1].as_slice()), (3, recovery[3].as_slice())];
        let result = Gf8::decode(k, m, 100, &orig, &rec).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_encode_decode_empty_data() {
        let k = 3;
        let m = 2;
        let data: Vec<Vec<u8>> = vec![vec![], vec![], vec![]];
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();

        let recovery = Gf8::encode(k, m, &refs).unwrap();
        assert!(recovery.iter().all(|s| s.is_empty()));

        let orig: Vec<(usize, &[u8])> = data.iter().enumerate().map(|(i, d)| (i, d.as_slice())).collect();
        let result = Gf8::decode(k, m, 0, &orig, &[]).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_too_many_shards() {
        let refs: Vec<&[u8]> = vec![&[0u8]; 200];
        let result = Gf8::encode(200, 56, &refs);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_shards() {
        let k = 85;
        let m = 170; // 85 + 170 = 255
        let data: Vec<Vec<u8>> = (0..k).map(|i| vec![i as u8; 32]).collect();
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();

        let recovery = Gf8::encode(k, m, &refs).unwrap();
        assert_eq!(recovery.len(), m);

        // Decode using only recovery shards
        let rec: Vec<(usize, &[u8])> = recovery
            .iter()
            .enumerate()
            .take(k)
            .map(|(i, d)| (i, d.as_slice()))
            .collect();
        let result = Gf8::decode(k, m, 32, &[], &rec).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_not_enough_shards() {
        let k = 3;
        let m = 2;
        let result = Gf8::decode(k, m, 10, &[(0, &[0u8; 10])], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_data() {
        let k = 33;
        let m = 67;
        let shard_len = 1024;
        let data: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..shard_len).map(|j| ((i * 37 + j * 13) % 256) as u8).collect())
            .collect();
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();

        let recovery = Gf8::encode(k, m, &refs).unwrap();

        // Lose first 20 originals, use 20 recovery shards instead
        let orig: Vec<(usize, &[u8])> = data
            .iter()
            .enumerate()
            .skip(20)
            .map(|(i, d)| (i, d.as_slice()))
            .collect();
        let rec: Vec<(usize, &[u8])> = recovery
            .iter()
            .enumerate()
            .take(20)
            .map(|(i, d)| (i, d.as_slice()))
            .collect();
        let result = Gf8::decode(k, m, shard_len, &orig, &rec).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_encoding_matrix_systematic() {
        // Verify that the encoding is systematic: encoding with identity reconstruction
        // yields the original data.
        let k = 5;
        let m = 3;
        let data: Vec<Vec<u8>> = (0..k).map(|i| vec![i as u8 + 1; 8]).collect();
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();

        let recovery = Gf8::encode(k, m, &refs).unwrap();

        // Decode using only originals (no recovery needed)
        let orig: Vec<(usize, &[u8])> = data.iter().enumerate().map(|(i, d)| (i, d.as_slice())).collect();
        let result = Gf8::decode(k, m, 8, &orig, &[]).unwrap();
        assert_eq!(result, data);

        // Also verify recovery shards are not all zeros (non-trivial encoding)
        assert!(recovery.iter().any(|s| s.iter().any(|&b| b != 0)));
    }

    #[test]
    fn test_all_subsets_decodable() {
        // For small parameters, verify every possible k-subset of n shards can decode
        let k = 3;
        let m = 2;
        let n = k + m;
        let data: Vec<Vec<u8>> = (0..k).map(|i| vec![(i + 1) as u8; 16]).collect();
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let recovery = Gf8::encode(k, m, &refs).unwrap();

        // Try all C(5,3) = 10 subsets
        for mask in 0u32..(1 << n) {
            if mask.count_ones() != k as u32 {
                continue;
            }
            let mut orig = Vec::new();
            let mut rec = Vec::new();
            for bit in 0..n {
                if mask & (1 << bit) != 0 {
                    if bit < k {
                        orig.push((bit, data[bit].as_slice()));
                    } else {
                        rec.push((bit - k, recovery[bit - k].as_slice()));
                    }
                }
            }
            let result = Gf8::decode(k, m, 16, &orig, &rec).unwrap();
            assert_eq!(result, data, "failed for mask={mask:#07b}");
        }
    }
}
