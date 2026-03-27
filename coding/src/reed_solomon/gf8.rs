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
    gf8_simd::{
        gf_2vect_dot_prod, gf_3vect_dot_prod, gf_4vect_dot_prod, gf_5vect_dot_prod,
        gf_6vect_dot_prod, gf_matrix_mul_zeroed_group, gf_vect_dot_prod, gf_vect_mad,
        gf_vect_mad_multi_raw,
    },
    Engine,
};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, RwLock},
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
    #[error("duplicate shard index: {0}")]
    DuplicateShardIndex(usize),
    #[error("invalid original shard index: {0}")]
    InvalidOriginalShardIndex(usize),
    #[error("invalid recovery shard index: {0}")]
    InvalidRecoveryShardIndex(usize),
    #[error("wrong number of original shards: got {got}, expected {expected}")]
    WrongShardCount { got: usize, expected: usize },
    #[error("inconsistent shard lengths")]
    InconsistentShardLengths,
    #[error("wrong shard length at index {index}: got {got}, expected {expected}")]
    WrongShardLength {
        index: usize,
        got: usize,
        expected: usize,
    },
    #[error("singular matrix (should not happen with valid parameters)")]
    SingularMatrix,
}

/// GF(2^8) Reed-Solomon engine with SIMD-accelerated field arithmetic.
///
/// Supports up to 255 total shards (k + m <= 255). Uses ISA-L-compatible
/// field arithmetic and GFNI affine tables.
#[derive(Clone, Debug)]
pub struct Gf8;

fn alloc_encode_recovery_shards(m: usize, shard_len: usize) -> Vec<Vec<u8>> {
    let mut recovery = Vec::with_capacity(m);
    for _ in 0..m {
        let mut shard = Vec::with_capacity(shard_len);
        // SAFETY: encode_matrix_mul always overwrites every byte of every recovery
        // shard before any read occurs. The small-output path zero-initializes its
        // destinations internally, and the grouped path zero-fills each destination
        // shard before falling back to accumulate kernels.
        unsafe {
            shard.set_len(shard_len);
        }
        recovery.push(shard);
    }
    recovery
}

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

        let enc_matrix = get_encoding_matrix(k, m)?;
        let mut recovery = alloc_encode_recovery_shards(m, shard_len);

        encode_matrix_mul(enc_matrix.as_ref(), k, &mut recovery, original);

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

        if provided_original.len() >= k {
            let mut originals = vec![None; k];
            for &(idx, shard) in provided_original.iter().take(k) {
                if idx >= k {
                    return Err(Error::InvalidOriginalShardIndex(idx));
                }
                if shard.len() != shard_len {
                    return Err(Error::WrongShardLength {
                        index: idx,
                        got: shard.len(),
                        expected: shard_len,
                    });
                }
                if originals[idx].is_some() {
                    return Err(Error::DuplicateShardIndex(idx));
                }
                originals[idx] = Some(shard.to_vec());
            }
            if let Some(result) = originals.into_iter().collect::<Option<Vec<_>>>() {
                return Ok(result);
            }
        }

        let mut seen = vec![false; n];
        for &(idx, shard) in provided_original {
            if idx >= k {
                return Err(Error::InvalidOriginalShardIndex(idx));
            }
            if shard.len() != shard_len {
                return Err(Error::WrongShardLength {
                    index: idx,
                    got: shard.len(),
                    expected: shard_len,
                });
            }
            if std::mem::replace(&mut seen[idx], true) {
                return Err(Error::DuplicateShardIndex(idx));
            }
        }
        for &(idx, shard) in provided_recovery {
            if idx >= m {
                return Err(Error::InvalidRecoveryShardIndex(idx));
            }
            if shard.len() != shard_len {
                return Err(Error::WrongShardLength {
                    index: k + idx,
                    got: shard.len(),
                    expected: shard_len,
                });
            }
            let full_idx = k + idx;
            if std::mem::replace(&mut seen[full_idx], true) {
                return Err(Error::DuplicateShardIndex(full_idx));
            }
        }

        // Build the encoding matrix (same as used for encoding)
        let enc_matrix = get_encoding_matrix(k, m)?;

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

        let selected_indices: Vec<usize> = selected.iter().map(|&(idx, _)| idx).collect();
        let inv_matrix = get_decode_matrix(k, m, enc_matrix.as_ref(), &selected_indices)?;

        // Multiply: result[j] = sum_i inv_matrix[j][i] * selected_data[i]
        let mut result = vec![vec![0u8; shard_len]; k];

        let selected_data: Vec<&[u8]> = selected.iter().map(|&(_, data)| data).collect();
        encode_matrix_mul(inv_matrix.as_ref(), k, &mut result, &selected_data);

        Ok(result)
    }
}

/// Maximum destinations per group. 34 destinations let the 50-chunk case fit in
/// a single group while keeping the working set close to the prior 32-destination
/// tuning.
const GROUP_SIZE: usize = 34;

/// Optimized matrix-vector multiply: `output[i] += sum_j matrix[i][j] * input[j]`.
///
/// `matrix` is row-major with `num_cols` columns and `output.len()` rows.
/// `input` has `num_cols` entries. All buffers in `output` must be zeroed on entry.
///
/// Destinations are processed in groups of [GROUP_SIZE] to keep the working set
/// in L2 cache. Zero coefficients are pre-filtered. No heap allocation occurs.
fn encode_matrix_mul(
    matrix: &[u8],
    num_cols: usize,
    output: &mut [Vec<u8>],
    input: &[&[u8]],
) {
    let num_rows = output.len();
    if num_rows == 0 || num_cols == 0 {
        return;
    }

    let shard_len = output[0].len();
    if shard_len == 0 {
        return;
    }

    if num_rows <= 6 {
        if encode_matrix_mul_small(matrix, num_cols, output, input) {
            return;
        }
    }

    // Fast path: when the entire output fits in a single group, fused SIMD kernels
    // overwrite all destination rows, so we can skip the explicit zero-fill.
    if num_rows <= GROUP_SIZE
        && gf_matrix_mul_zeroed_group(matrix, num_cols, output, input)
    {
        return;
    }

    // Stack-allocated buffers for pre-filtered coefficients and destination pointers.
    let mut coeffs = [0u8; GROUP_SIZE];
    let mut dsts_ptrs: [*mut u8; GROUP_SIZE] = [std::ptr::null_mut(); GROUP_SIZE];

    for group_start in (0..num_rows).step_by(GROUP_SIZE) {
        let group_end = (group_start + GROUP_SIZE).min(num_rows);
        let group_len = group_end - group_start;
        let matrix_rows = &matrix[group_start * num_cols..group_end * num_cols];

        // Fast path: GFNI+AVX2 fused matrix multiply overwrites the full group,
        // including any scalar tail, so it can run before explicit zeroing.
        if gf_matrix_mul_zeroed_group(
            matrix_rows,
            num_cols,
            &mut output[group_start..group_end],
            input,
        ) {
            continue;
        }

        for row in &mut output[group_start..group_end] {
            row.fill(0);
        }

        for j in 0..num_cols {
            // Pre-filter: collect only non-zero coefficients and their destination
            // pointers on the stack. This eliminates branches in the SIMD inner loop.
            let mut count = 0;
            for gi in 0..group_len {
                let c = matrix_rows[gi * num_cols + j];
                if c != 0 {
                    coeffs[count] = c;
                    dsts_ptrs[count] = output[group_start + gi].as_mut_ptr();
                    count += 1;
                }
            }

            if count == 0 {
                continue;
            }

            if count == 1 {
                // SAFETY: dsts_ptrs[0] is from output[i] which has shard_len allocated bytes.
                let dst =
                    unsafe { std::slice::from_raw_parts_mut(dsts_ptrs[0], shard_len) };
                gf_vect_mad(dst, input[j], coeffs[0]);
            } else {
                // SAFETY: pointers from distinct output Vecs, non-overlapping.
                unsafe {
                    gf_vect_mad_multi_raw(
                        &dsts_ptrs[..count],
                        input[j],
                        &coeffs[..count],
                        shard_len,
                    );
                }
            }
        }
    }
}

fn encode_matrix_mul_small(
    matrix: &[u8],
    num_cols: usize,
    output: &mut [Vec<u8>],
    input: &[&[u8]],
) -> bool {
    match output.len() {
        1 => {
            let coeffs = &matrix[..num_cols];
            gf_vect_dot_prod(output[0].as_mut_slice(), input, coeffs);
            true
        }
        2 => {
            let mut coeffs = vec![[0u8; 2]; num_cols];
            for col in 0..num_cols {
                coeffs[col][0] = matrix[col];
                coeffs[col][1] = matrix[num_cols + col];
            }
            let (first, rest) = output.split_at_mut(1);
            let mut dsts = [first[0].as_mut_slice(), rest[0].as_mut_slice()];
            gf_2vect_dot_prod(&mut dsts, input, &coeffs);
            true
        }
        3 => {
            let mut coeffs = vec![[0u8; 3]; num_cols];
            for col in 0..num_cols {
                coeffs[col][0] = matrix[col];
                coeffs[col][1] = matrix[num_cols + col];
                coeffs[col][2] = matrix[2 * num_cols + col];
            }
            let (a, rest) = output.split_at_mut(1);
            let (b, c) = rest.split_at_mut(1);
            let mut dsts = [a[0].as_mut_slice(), b[0].as_mut_slice(), c[0].as_mut_slice()];
            gf_3vect_dot_prod(&mut dsts, input, &coeffs);
            true
        }
        4 => {
            let mut coeffs = vec![[0u8; 4]; num_cols];
            for col in 0..num_cols {
                coeffs[col][0] = matrix[col];
                coeffs[col][1] = matrix[num_cols + col];
                coeffs[col][2] = matrix[2 * num_cols + col];
                coeffs[col][3] = matrix[3 * num_cols + col];
            }
            let (a, rest) = output.split_at_mut(1);
            let (b, rest) = rest.split_at_mut(1);
            let (c, d) = rest.split_at_mut(1);
            let mut dsts = [
                a[0].as_mut_slice(),
                b[0].as_mut_slice(),
                c[0].as_mut_slice(),
                d[0].as_mut_slice(),
            ];
            gf_4vect_dot_prod(&mut dsts, input, &coeffs);
            true
        }
        5 => {
            let mut coeffs = vec![[0u8; 5]; num_cols];
            for col in 0..num_cols {
                coeffs[col][0] = matrix[col];
                coeffs[col][1] = matrix[num_cols + col];
                coeffs[col][2] = matrix[2 * num_cols + col];
                coeffs[col][3] = matrix[3 * num_cols + col];
                coeffs[col][4] = matrix[4 * num_cols + col];
            }
            let (a, rest) = output.split_at_mut(1);
            let (b, rest) = rest.split_at_mut(1);
            let (c, rest) = rest.split_at_mut(1);
            let (d, e) = rest.split_at_mut(1);
            let mut dsts = [
                a[0].as_mut_slice(),
                b[0].as_mut_slice(),
                c[0].as_mut_slice(),
                d[0].as_mut_slice(),
                e[0].as_mut_slice(),
            ];
            gf_5vect_dot_prod(&mut dsts, input, &coeffs);
            true
        }
        6 => {
            let mut coeffs = vec![[0u8; 6]; num_cols];
            for col in 0..num_cols {
                coeffs[col][0] = matrix[col];
                coeffs[col][1] = matrix[num_cols + col];
                coeffs[col][2] = matrix[2 * num_cols + col];
                coeffs[col][3] = matrix[3 * num_cols + col];
                coeffs[col][4] = matrix[4 * num_cols + col];
                coeffs[col][5] = matrix[5 * num_cols + col];
            }
            let (a, rest) = output.split_at_mut(1);
            let (b, rest) = rest.split_at_mut(1);
            let (c, rest) = rest.split_at_mut(1);
            let (d, rest) = rest.split_at_mut(1);
            let (e, f) = rest.split_at_mut(1);
            let mut dsts = [
                a[0].as_mut_slice(),
                b[0].as_mut_slice(),
                c[0].as_mut_slice(),
                d[0].as_mut_slice(),
                e[0].as_mut_slice(),
                f[0].as_mut_slice(),
            ];
            gf_6vect_dot_prod(&mut dsts, input, &coeffs);
            true
        }
        _ => false,
    }
}

/// Build the encoding matrix (m x k) for systematic Reed-Solomon.
///
/// This follows ISA-L's `gf_gen_rs_matrix` layout directly: the full code matrix
/// is systematic, with identity rows for originals and parity rows generated from
/// successive powers of generator `2`. We return only the parity rows.
fn build_encoding_matrix(k: usize, m: usize) -> Result<Vec<u8>, Error> {
    if m == 0 {
        return Ok(vec![]);
    }

    let mut enc = vec![0u8; m * k];
    let mut gen = 1u8;
    for i in 0..m {
        let mut p = 1u8;
        for value in &mut enc[i * k..(i + 1) * k] {
            *value = p;
            p = mul(p, gen);
        }
        gen = mul(gen, 2);
    }

    Ok(enc)
}

fn get_encoding_matrix(k: usize, m: usize) -> Result<Arc<[u8]>, Error> {
    type Cache = RwLock<HashMap<(usize, usize), Arc<[u8]>>>;

    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));

    {
        let read = cache.read().expect("encoding matrix cache poisoned");
        if let Some(matrix) = read.get(&(k, m)) {
            return Ok(Arc::clone(matrix));
        }
    }

    let matrix: Arc<[u8]> = build_encoding_matrix(k, m)?.into();
    let mut write = cache.write().expect("encoding matrix cache poisoned");
    Ok(Arc::clone(
        write.entry((k, m)).or_insert_with(|| Arc::clone(&matrix)),
    ))
}

fn get_decode_matrix(
    k: usize,
    m: usize,
    enc_matrix: &[u8],
    selected_indices: &[usize],
) -> Result<Arc<[u8]>, Error> {
    type Cache = RwLock<HashMap<(usize, usize, Box<[usize]>), Arc<[u8]>>>;

    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    let key = (k, m, selected_indices.to_vec().into_boxed_slice());

    {
        let read = cache.read().expect("decode matrix cache poisoned");
        if let Some(matrix) = read.get(&key) {
            return Ok(Arc::clone(matrix));
        }
    }

    // Build the k x k submatrix from selected rows of the full code matrix.
    // The full code matrix is:
    //   rows 0..k:   identity matrix (original shards)
    //   rows k..n:   encoding matrix (recovery shards)
    let mut submatrix = vec![0u8; k * k];
    for (row, &idx) in selected_indices.iter().enumerate() {
        if idx < k {
            submatrix[row * k + idx] = 1;
        } else {
            let enc_row = idx - k;
            submatrix[row * k..row * k + k]
                .copy_from_slice(&enc_matrix[enc_row * k..enc_row * k + k]);
        }
    }

    let matrix: Arc<[u8]> = invert_matrix(&submatrix, k)?.into();
    let mut write = cache.write().expect("decode matrix cache poisoned");
    Ok(Arc::clone(
        write.entry(key).or_insert_with(|| Arc::clone(&matrix)),
    ))
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
    fn test_decode_rejects_invalid_original_index() {
        let result = Gf8::decode(3, 2, 8, &[(3, &[0u8; 8]), (1, &[0u8; 8]), (2, &[0u8; 8])], &[]);
        assert!(matches!(result, Err(Error::InvalidOriginalShardIndex(3))));
    }

    #[test]
    fn test_decode_rejects_invalid_recovery_index() {
        let result = Gf8::decode(3, 2, 8, &[], &[(0, &[0u8; 8]), (1, &[0u8; 8]), (2, &[0u8; 8])]);
        assert!(matches!(result, Err(Error::InvalidRecoveryShardIndex(2))));
    }

    #[test]
    fn test_decode_rejects_duplicate_original_index() {
        let result = Gf8::decode(
            3,
            2,
            8,
            &[(0, &[0u8; 8]), (0, &[1u8; 8]), (1, &[2u8; 8])],
            &[],
        );
        assert!(matches!(result, Err(Error::DuplicateShardIndex(0))));
    }

    #[test]
    fn test_decode_rejects_duplicate_recovery_index() {
        let result = Gf8::decode(
            3,
            2,
            8,
            &[(0, &[0u8; 8])],
            &[(1, &[1u8; 8]), (1, &[2u8; 8]), (0, &[3u8; 8])],
        );
        assert!(matches!(result, Err(Error::DuplicateShardIndex(4))));
    }

    #[test]
    fn test_decode_rejects_wrong_shard_length() {
        let result = Gf8::decode(3, 2, 8, &[(0, &[0u8; 8]), (1, &[1u8; 7]), (2, &[2u8; 8])], &[]);
        assert!(matches!(
            result,
            Err(Error::WrongShardLength {
                index: 1,
                got: 7,
                expected: 8
            })
        ));
    }

    #[test]
    fn test_encoding_matrix_cache_reuses_matrix() {
        let first = get_encoding_matrix(8, 4).unwrap();
        let second = get_encoding_matrix(8, 4).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
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
