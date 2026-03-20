//! Encoding stage: polynomial to matrix to Reed-Solomon to Merkle commitment.
//!
//! This module implements the Ligero commitment: arrange polynomial
//! coefficients as a matrix, RS-encode each column, hash rows into
//! a Merkle tree.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryFieldElement;
use crate::merkle::{self, Hash};
use crate::proof::{Commitment, Witness};
use crate::reed_solomon::ReedSolomon;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Arrange polynomial coefficients into a matrix and RS-encode columns.
fn poly_to_encoded_matrix<F: BinaryFieldElement + Send + Sync + bytemuck::Pod + 'static>(
    poly: &[F],
    m: usize,
    n: usize,
    inv_rate: usize,
    rs: &ReedSolomon<F>,
) -> Vec<Vec<F>> {
    let m_target = m * inv_rate;
    let mut mat = vec![vec![F::zero(); n]; m_target];

    // Transpose polynomial into matrix (column-major to row-major)
    #[cfg(feature = "parallel")]
    {
        mat.par_iter_mut().enumerate().for_each(|(i, row)| {
            for j in 0..n {
                let idx = j * m + i;
                if idx < poly.len() {
                    row[j] = poly[idx];
                }
            }
        });
    }

    #[cfg(not(feature = "parallel"))]
    {
        for (i, row) in mat.iter_mut().enumerate() {
            for j in 0..n {
                let idx = j * m + i;
                if idx < poly.len() {
                    row[j] = poly[idx];
                }
            }
        }
    }

    // RS-encode each column
    let n_cols = mat[0].len();

    #[cfg(feature = "parallel")]
    {
        let cols: Vec<Vec<F>> = (0..n_cols)
            .into_par_iter()
            .map(|j| {
                let mut col: Vec<F> = mat.iter().map(|row| row[j]).collect();
                crate::reed_solomon::encode_in_place_with_parallel(rs, &mut col, false);
                col
            })
            .collect();

        for (i, row) in mat.iter_mut().enumerate() {
            for (j, col) in cols.iter().enumerate() {
                row[j] = col[i];
            }
        }
    }

    #[cfg(not(feature = "parallel"))]
    {
        for j in 0..n_cols {
            let mut col: Vec<F> = mat.iter().map(|row| row[j]).collect();
            crate::reed_solomon::encode_in_place(rs, &mut col);
            for (i, val) in col.iter().enumerate() {
                mat[i][j] = *val;
            }
        }
    }

    mat
}

/// Hash a row of field elements using BLAKE3.
///
/// Produces the leaf digest for the Merkle tree. Uses BLAKE3 (same as
/// the interior nodes) to avoid mixing hash functions.
#[inline(always)]
pub(crate) fn hash_row<F: BinaryFieldElement>(row: &[F]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(row.len() as u32).to_le_bytes());

    // SAFETY: Field elements are plain data (repr(transparent) over
    // primitive integers) with no padding. Viewing the contiguous slice
    // as bytes for hashing is sound.
    let row_bytes = unsafe {
        core::slice::from_raw_parts(row.as_ptr() as *const u8, core::mem::size_of_val(row))
    };
    hasher.update(row_bytes);

    *hasher.finalize().as_bytes()
}

/// Commit to a polynomial: encode as matrix, hash rows, build Merkle tree.
pub(crate) fn ligero_commit<F: BinaryFieldElement + Send + Sync + bytemuck::Pod + 'static>(
    poly: &[F],
    m: usize,
    n: usize,
    rs: &ReedSolomon<F>,
) -> Witness<F> {
    let mat = poly_to_encoded_matrix(poly, m, n, 4, rs);

    // Hash rows for Merkle leaves
    #[cfg(feature = "parallel")]
    let hashed_rows: Vec<Hash> = mat.par_iter().map(|row| hash_row(row)).collect();

    #[cfg(not(feature = "parallel"))]
    let hashed_rows: Vec<Hash> = mat.iter().map(|row| hash_row(row)).collect();

    let tree = merkle::build_merkle_tree_from_hashes(&hashed_rows);

    Witness { mat, tree }
}

/// Extract commitment from a witness.
pub(crate) fn commitment_from_witness<F: BinaryFieldElement>(witness: &Witness<F>) -> Commitment {
    Commitment {
        root: witness.tree.get_root(),
    }
}
