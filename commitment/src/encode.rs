//! Encoding stage: polynomial to column-major matrix, RS-encode in-place,
//! hash rows into a Merkle tree.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryFieldElement;
use crate::merkle::{self, Hash};
use crate::proof::{Commitment, Witness};
use crate::reed_solomon::ReedSolomon;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Build a column-major flat matrix from polynomial coefficients and
/// RS-encode each column in-place.
///
/// The polynomial `poly[j * m + i]` maps to column `j`, row `i`.
/// Columns are contiguous in memory, so RS encoding has perfect
/// spatial locality.
pub(crate) fn build_and_encode<F: BinaryFieldElement + Send + Sync + bytemuck::Pod + 'static>(
    poly: &[F],
    m: usize,
    n: usize,
    inv_rate: usize,
    rs: &ReedSolomon<F>,
) -> (Vec<F>, usize, usize) {
    let m_target = m * inv_rate;
    let mut data = vec![F::zero(); m_target * n];

    // Fill column-major: poly[j*m + i] -> data[j*m_target + i]
    for j in 0..n {
        let col_start = j * m_target;
        for i in 0..m {
            let poly_idx = j * m + i;
            if poly_idx < poly.len() {
                data[col_start + i] = poly[poly_idx];
            }
        }
    }

    // RS-encode each column in-place (contiguous slice per column)
    #[cfg(feature = "parallel")]
    {
        data.par_chunks_mut(m_target).for_each(|col| {
            crate::reed_solomon::encode_in_place_with_parallel(rs, col, false);
        });
    }

    #[cfg(not(feature = "parallel"))]
    {
        for j in 0..n {
            let start = j * m_target;
            let col = &mut data[start..start + m_target];
            crate::reed_solomon::encode_in_place(rs, col);
        }
    }

    (data, m_target, n)
}

/// Hash row `i` from a column-major flat buffer.
///
/// Gathers the row into a contiguous buffer first, then hashes
/// identically to [`crate::utils::hash_row`] for prover/verifier
/// consistency.
#[inline]
pub(crate) fn hash_row_colmajor<F: BinaryFieldElement>(data: &[F], rows: usize, cols: usize, i: usize) -> Hash {
    let mut row_buf = vec![F::zero(); cols];
    for j in 0..cols {
        row_buf[j] = data[j * rows + i];
    }
    crate::utils::hash_row(&row_buf)
}

/// Commit to a polynomial: encode as column-major matrix, hash rows,
/// build Merkle tree.
pub(crate) fn ligero_commit<F: BinaryFieldElement + Send + Sync + bytemuck::Pod + 'static>(
    poly: &[F],
    m: usize,
    n: usize,
    rs: &ReedSolomon<F>,
) -> Witness<F> {
    let (data, rows, cols) = build_and_encode(poly, m, n, 4, rs);

    // Hash rows (strided gather from column-major layout)
    #[cfg(feature = "parallel")]
    let hashed_rows: Vec<Hash> = (0..rows)
        .into_par_iter()
        .map(|i| hash_row_colmajor(&data, rows, cols, i))
        .collect();

    #[cfg(not(feature = "parallel"))]
    let hashed_rows: Vec<Hash> = (0..rows)
        .map(|i| hash_row_colmajor(&data, rows, cols, i))
        .collect();

    let tree = merkle::build_merkle_tree_from_hashes(&hashed_rows);

    Witness {
        data,
        rows,
        cols,
        tree,
    }
}

/// Extract commitment from a witness.
pub(crate) fn commitment_from_witness<F: BinaryFieldElement>(witness: &Witness<F>) -> Commitment {
    Commitment {
        root: witness.tree.get_root(),
    }
}
