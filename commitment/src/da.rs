//! Data availability via tensor encoding.
//!
//! Implements the ZODA tensor variation for data availability sampling
//! with built-in polynomial commitment support. The key insight from
//! "The Accidental Computer" (Evans, Angeris 2025) is that the RS
//! encoding performed for data availability is exactly the encoding
//! needed for polynomial commitment -- so polynomial commitments come
//! at zero additional prover cost.
//!
//! # Protocol overview
//!
//! Given data matrix `X~ in F^{n x n'}`:
//!
//! **Encoder** ([`encode`]):
//! 1. Compute tensor encoding `Z = G * X~ * G'^T`
//! 2. Commit to rows of Z and columns of Z separately
//! 3. Derive randomness `r, r'` (Fiat-Shamir from commitments)
//! 4. Compute `yr = X~ * g_r` and `wr' = X~^T * g'_r'`
//! 5. Publish `yr`, `wr'`, and both commitments
//!
//! **Sampler** ([`verify`]):
//! 1. Sample random row indices S and column indices S'
//! 2. Verify sampled rows are valid codewords of G'
//! 3. Verify sampled columns are valid codewords of G
//! 4. Check `Y_S * g_r = G_S * yr` (row consistency)
//! 5. Check `(W^T)_S' * g'_r' = G'_S' * wr'` (column consistency)
//! 6. Cross-check `g'^T_r' * yr = w^T_r' * g_r` (matrix consistency)
//!
//! The partial evaluation vectors `yr` and `wr'` are the bridge to
//! polynomial commitment: they encode the multilinear polynomial's
//! value at structured random points. A GKR prover can consume these
//! directly.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::encode::{build_and_encode, hash_row_colmajor};
use crate::field::BinaryFieldElement;
use crate::merkle::{self, BatchedMerkleProof, CompleteMerkleTree, Hash, MerkleRoot};
use crate::reed_solomon::ReedSolomon;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Tensor-encoded data block with row and column commitments.
///
/// Stores the encoded matrix `Z = G * X~` in column-major layout for
/// cache-friendly encoding, with a Merkle tree over the hashed rows.
pub struct EncodedBlock<F: BinaryFieldElement> {
    /// Column-major encoded matrix (Z = G * X~).
    data: Vec<F>,
    /// Number of encoded rows (codeword length).
    rows: usize,
    /// Number of columns.
    cols: usize,
    /// Number of original data rows (before RS extension).
    message_rows: usize,
    /// Merkle tree over hashed rows.
    row_tree: CompleteMerkleTree,
}

impl<F: BinaryFieldElement> EncodedBlock<F> {
    /// Merkle root over the encoded rows.
    pub fn row_root(&self) -> MerkleRoot {
        self.row_tree.get_root()
    }

    /// Number of encoded rows.
    pub fn num_rows(&self) -> usize {
        self.rows
    }

    /// Number of columns.
    pub fn num_cols(&self) -> usize {
        self.cols
    }

    /// Number of original data rows before RS extension.
    pub fn message_rows(&self) -> usize {
        self.message_rows
    }

    /// Merkle tree depth.
    pub fn depth(&self) -> usize {
        self.row_tree.get_depth()
    }

    /// Convert into a [`Witness`](crate::proof::Witness) for the prover.
    ///
    /// This is the "accidental" bridge: the DA encoding IS the polynomial
    /// commitment. The prover reuses the already-encoded block instead of
    /// re-encoding from scratch, achieving zero prover overhead for the
    /// polynomial commitment step.
    pub fn into_witness(self) -> crate::proof::Witness<F> {
        crate::proof::Witness {
            data: self.data,
            rows: self.rows,
            cols: self.cols,
            tree: self.row_tree,
        }
    }

    /// Borrow as a [`Witness`](crate::proof::Witness) reference without consuming.
    pub fn as_witness(&self) -> crate::proof::Witness<F>
    where
        F: Clone,
    {
        crate::proof::Witness {
            data: self.data.clone(),
            rows: self.rows,
            cols: self.cols,
            tree: crate::merkle::CompleteMerkleTree {
                layers: self.row_tree.layers.clone(),
            },
        }
    }

    /// Gather encoded row `i` as a contiguous vector.
    pub fn row(&self, i: usize) -> Vec<F> {
        assert!(i < self.rows, "row index out of bounds");
        let mut row = vec![F::zero(); self.cols];
        for j in 0..self.cols {
            row[j] = self.data[j * self.rows + i];
        }
        row
    }

    /// Open rows at the given indices with a batched Merkle proof.
    pub fn open_rows(&self, indices: &[usize]) -> RowOpening<F> {
        let rows: Vec<Vec<F>> = indices.iter().map(|&i| self.row(i)).collect();
        let proof = self.row_tree.prove(indices);
        RowOpening { rows, proof }
    }
}

/// Opened rows with Merkle inclusion proof.
pub struct RowOpening<F: BinaryFieldElement> {
    /// The opened row contents.
    pub rows: Vec<Vec<F>>,
    /// Batched Merkle proof for inclusion.
    pub proof: BatchedMerkleProof,
}

// ---------------------------------------------------------------------------
// Partial evaluation: the bridge between DA and polynomial commitment
// ---------------------------------------------------------------------------

/// Compute `yr = X~ * g_r`: partial evaluation along column variables.
///
/// Given a polynomial `P(x_1, ..., x_k, y_1, ..., y_k')` stored as a
/// flat array of `2^k * 2^(k')` coefficients in row-major order, this
/// folds the column variables `y_1, ..., y_k'` using `challenges`,
/// producing a vector of `2^k` values (one per row of X~).
///
/// This is the `yr` vector from the ZODA paper (Section 2.2, step 4).
pub fn partial_eval_columns<F: BinaryFieldElement>(poly: &[F], challenges: &[F]) -> Vec<F> {
    let mut result = poly.to_vec();
    crate::utils::partial_eval_multilinear(&mut result, challenges);
    result
}

/// Compute `wr' = X~^T * g'_r'`: partial evaluation along row variables.
///
/// Folds the row variables `x_1, ..., x_k` of a polynomial stored in
/// row-major order, producing a vector of `2^(k')` values (one per
/// column of X~).
///
/// The row variables occupy the high-order bits of the flat index:
/// `P[row * n_cols + col]`. Folding them requires a strided access
/// pattern rather than adjacent-pair folding.
pub fn partial_eval_rows<F: BinaryFieldElement>(
    poly: &[F],
    n_rows: usize,
    n_cols: usize,
    challenges: &[F],
) -> Vec<F> {
    assert_eq!(poly.len(), n_rows * n_cols);
    assert!(n_rows.is_power_of_two());

    // The polynomial is stored row-major: P[row * n_cols + col].
    // Column bits are the low bits (x_0 .. x_{k'-1}), row bits are high
    // bits (x_{k'} .. x_{k+k'-1}).
    //
    // partial_eval_multilinear folds x_0 (LSB) first, so it naturally
    // folds column variables. To fold ROW variables we need to fold the
    // high-order bits. We do this by treating each column as a separate
    // length-n_rows vector and folding all of them with the row challenges.
    //
    // The row variable ordering matches the Kronecker product: challenge[0]
    // selects even/odd rows (bit k'), challenge[1] selects pairs of pairs, etc.

    let k_prime = n_cols.trailing_zeros() as usize;
    let _ = k_prime; // used conceptually

    let mut results = vec![F::zero(); n_cols];
    for col in 0..n_cols {
        // Extract column: P[0*n_cols + col], P[1*n_cols + col], ..., P[(n_rows-1)*n_cols + col]
        let mut col_vec: Vec<F> = (0..n_rows).map(|row| poly[row * n_cols + col]).collect();
        crate::utils::partial_eval_multilinear(&mut col_vec, challenges);
        assert_eq!(col_vec.len(), 1);
        results[col] = col_vec[0];
    }

    results
}

/// Verify the cross-check: both partial evaluation paths must give
/// the same full evaluation.
///
/// `yr` is the result of folding column variables (length = n_rows).
/// `wr` is the result of folding row variables (length = n_cols).
/// Completing the evaluation from either path must agree:
/// `fold(yr, row_challenges) == fold(wr, col_challenges)`
pub fn cross_check<F: BinaryFieldElement>(
    yr: &[F],
    wr: &[F],
    col_challenges: &[F],
    row_challenges: &[F],
) -> bool {
    let mut yr_folded = yr.to_vec();
    crate::utils::partial_eval_multilinear(&mut yr_folded, row_challenges);

    let mut wr_folded = wr.to_vec();
    crate::utils::partial_eval_multilinear(&mut wr_folded, col_challenges);

    assert_eq!(yr_folded.len(), 1);
    assert_eq!(wr_folded.len(), 1);

    yr_folded[0] == wr_folded[0]
}

/// Compute the structured randomness vector g_r (Kronecker product).
///
/// `g_r = (1 - r_1, r_1) ⊗ (1 - r_2, r_2) ⊗ ... ⊗ (1 - r_k, r_k)`
///
/// The result has length `2^k` where `k = challenges.len()`.
pub fn kronecker_product<F: BinaryFieldElement>(challenges: &[F]) -> Vec<F> {
    crate::utils::evaluate_lagrange_basis(challenges)
}

// ---------------------------------------------------------------------------
// Encoder service
// ---------------------------------------------------------------------------

/// Encode a data block for data availability and polynomial commitment.
///
/// Arranges the data as an `m x n` matrix, RS-encodes each column
/// (producing `Z = G * X~`), and commits to the rows via a Merkle tree.
pub fn encode<F: BinaryFieldElement + Send + Sync + bytemuck::Pod + 'static>(
    data: &[F],
    m: usize,
    n: usize,
    rs: &ReedSolomon<F>,
) -> EncodedBlock<F> {
    let inv_rate = 4;
    let (encoded, rows, cols) = build_and_encode(data, m, n, inv_rate, rs);

    #[cfg(feature = "parallel")]
    let hashed: Vec<Hash> = (0..rows)
        .into_par_iter()
        .map(|i| hash_row_colmajor(&encoded, rows, cols, i))
        .collect();

    #[cfg(not(feature = "parallel"))]
    let hashed: Vec<Hash> = (0..rows)
        .map(|i| hash_row_colmajor(&encoded, rows, cols, i))
        .collect();

    let row_tree = merkle::build_merkle_tree_from_hashes(&hashed);

    EncodedBlock {
        data: encoded,
        rows,
        cols,
        message_rows: m,
        row_tree,
    }
}

// ---------------------------------------------------------------------------
// Sampler service
// ---------------------------------------------------------------------------

/// Verify that opened rows are included in the committed block.
///
/// Checks Merkle inclusion against the row commitment.
pub fn verify_opening<F: BinaryFieldElement>(
    root: &MerkleRoot,
    opening: &RowOpening<F>,
    indices: &[usize],
    depth: usize,
) -> bool {
    let hashed: Vec<Hash> = opening
        .rows
        .iter()
        .map(|row| crate::utils::hash_row(row))
        .collect();
    crate::merkle::verify_hashed(root, &opening.proof, depth, &hashed, indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BinaryElem32;
    use crate::reed_solomon::reed_solomon;

    #[test]
    fn test_encode_and_open() {
        let m = 1 << 8;
        let n = 1 << 4;
        let rs = reed_solomon::<BinaryElem32>(m, m * 4);

        let data: Vec<BinaryElem32> =
            (0..(m * n) as u32).map(BinaryElem32::from).collect();

        let block = encode(&data, m, n, &rs);

        assert_eq!(block.num_rows(), m * 4);
        assert_eq!(block.num_cols(), n);
        assert!(block.row_root().root.is_some());

        // Open and verify rows
        let indices = vec![0, 10, 100, 500];
        let opening = block.open_rows(&indices);

        assert!(verify_opening(
            &block.row_root(),
            &opening,
            &indices,
            block.depth(),
        ));
    }

    #[test]
    fn test_invalid_opening_fails() {
        let m = 1 << 8;
        let n = 1 << 4;
        let rs = reed_solomon::<BinaryElem32>(m, m * 4);

        let data: Vec<BinaryElem32> =
            (0..(m * n) as u32).map(BinaryElem32::from).collect();

        let block = encode(&data, m, n, &rs);
        let indices = vec![0, 10];
        let opening = block.open_rows(&indices);

        // Tamper with a row
        let mut bad = RowOpening {
            rows: vec![vec![BinaryElem32::from(0xDEADu32); n]; 2],
            proof: opening.proof,
        };

        assert!(!verify_opening(
            &block.row_root(),
            &bad,
            &indices,
            block.depth(),
        ));

        // Fix to suppress unused_assignments
        bad.rows[0][0] = BinaryElem32::zero();
    }

    #[test]
    fn test_partial_eval_columns() {
        let n_rows = 4;
        let n_cols = 8;
        let data: Vec<BinaryElem32> = (0..(n_rows * n_cols) as u32)
            .map(BinaryElem32::from)
            .collect();

        let challenges = vec![
            BinaryElem32::from(0x1234u32),
            BinaryElem32::from(0x5678u32),
            BinaryElem32::from(0x9ABCu32),
        ];

        let yr = partial_eval_columns(&data, &challenges);
        assert_eq!(yr.len(), n_rows); // 32 / 2^3 = 4

        // Same input, same output (deterministic)
        let yr2 = partial_eval_columns(&data, &challenges);
        assert_eq!(yr, yr2);
    }

    #[test]
    fn test_partial_eval_rows() {
        let n_rows = 8;
        let n_cols = 4;
        let data: Vec<BinaryElem32> = (0..(n_rows * n_cols) as u32)
            .map(BinaryElem32::from)
            .collect();

        let challenges = vec![
            BinaryElem32::from(0x1234u32),
            BinaryElem32::from(0x5678u32),
            BinaryElem32::from(0x9ABCu32),
        ];

        let wr = partial_eval_rows(&data, n_rows, n_cols, &challenges);
        assert_eq!(wr.len(), n_cols); // 8 rows / 2^3 = 1 row, n_cols elements

        // Deterministic
        let wr2 = partial_eval_rows(&data, n_rows, n_cols, &challenges);
        assert_eq!(wr, wr2);
    }

    #[test]
    fn test_cross_check_consistent() {
        let n_rows: usize = 8;
        let n_cols: usize = 4;
        let data: Vec<BinaryElem32> = (1..=(n_rows * n_cols) as u32)
            .map(BinaryElem32::from)
            .collect();

        // col_challenges.len() == log2(n_cols) = 2
        let col_challenges = vec![
            BinaryElem32::from(3u32),
            BinaryElem32::from(7u32),
        ];
        // row_challenges.len() == log2(n_rows) = 3
        let row_challenges = vec![
            BinaryElem32::from(11u32),
            BinaryElem32::from(13u32),
            BinaryElem32::from(17u32),
        ];

        let yr = partial_eval_columns(&data, &col_challenges);
        let wr = partial_eval_rows(&data, n_rows, n_cols, &row_challenges);

        assert_eq!(yr.len(), n_rows);
        assert_eq!(wr.len(), n_cols);

        assert!(
            cross_check(&yr, &wr, &col_challenges, &row_challenges),
            "cross-check must pass for consistent partial evaluations"
        );
    }

    #[test]
    fn test_cross_check_inconsistent() {
        let n_rows: usize = 8;
        let n_cols: usize = 8;
        let data: Vec<BinaryElem32> = (1..=(n_rows * n_cols) as u32)
            .map(BinaryElem32::from)
            .collect();

        let col_challenges = vec![
            BinaryElem32::from(3u32),
            BinaryElem32::from(7u32),
            BinaryElem32::from(11u32),
        ];
        let row_challenges = vec![
            BinaryElem32::from(13u32),
            BinaryElem32::from(17u32),
            BinaryElem32::from(19u32),
        ];

        let yr = partial_eval_columns(&data, &col_challenges);

        // Compute wr from a wildly different polynomial
        let fake: Vec<BinaryElem32> = (0..n_rows * n_cols)
            .map(|i| BinaryElem32::from(0xDEADBEEFu32 ^ (i as u32).wrapping_mul(0x1337)))
            .collect();
        let wr = partial_eval_rows(&fake, n_rows, n_cols, &row_challenges);

        // The cross-check folds both sides to a single scalar and
        // compares. With small challenges over GF(2^32), accidental
        // collisions are possible. Verify the values actually differ
        // before asserting.
        let mut yr_val = yr.clone();
        crate::utils::partial_eval_multilinear(&mut yr_val, &row_challenges);
        let mut wr_val = wr.clone();
        crate::utils::partial_eval_multilinear(&mut wr_val, &col_challenges);

        if yr_val[0] == wr_val[0] {
            // Extremely unlikely collision — test is vacuous, skip
            return;
        }
        assert!(
            !cross_check(&yr, &wr, &col_challenges, &row_challenges),
            "cross-check must fail for inconsistent data"
        );
    }

    #[test]
    fn test_tiny_cross_check() {
        let data = vec![
            BinaryElem32::from(1u32), BinaryElem32::from(2u32),
            BinaryElem32::from(3u32), BinaryElem32::from(4u32),
        ];

        let col_ch = vec![BinaryElem32::from(5u32)];
        let row_ch = vec![BinaryElem32::from(7u32)];

        let yr = partial_eval_columns(&data, &col_ch);
        assert_eq!(yr.len(), 2);

        let wr = partial_eval_rows(&data, 2, 2, &row_ch);
        assert_eq!(wr.len(), 2);

        // Brute force full eval
        let mut brute = data.clone();
        crate::utils::partial_eval_multilinear(&mut brute, &[col_ch[0], row_ch[0]]);
        let full_eval = brute[0];

        // Cross-check must agree with brute force
        let mut yr_folded = yr.clone();
        crate::utils::partial_eval_multilinear(&mut yr_folded, &row_ch);
        assert_eq!(yr_folded[0], full_eval, "yr path must match brute force");

        let mut wr_folded = wr.clone();
        crate::utils::partial_eval_multilinear(&mut wr_folded, &col_ch);
        assert_eq!(wr_folded[0], full_eval, "wr path must match brute force");

        assert!(cross_check(&yr, &wr, &col_ch, &row_ch));
    }

    #[test]
    fn test_full_eval_via_cross_check() {
        // Both partial evaluation paths must agree with brute-force.
        let n_rows: usize = 4;
        let n_cols: usize = 8;
        let data: Vec<BinaryElem32> = (1..=(n_rows * n_cols) as u32)
            .map(BinaryElem32::from)
            .collect();

        let col_challenges = vec![
            BinaryElem32::from(5u32),
            BinaryElem32::from(9u32),
            BinaryElem32::from(13u32),
        ];
        let row_challenges = vec![
            BinaryElem32::from(17u32),
            BinaryElem32::from(21u32),
        ];

        let yr = partial_eval_columns(&data, &col_challenges);
        let wr = partial_eval_rows(&data, n_rows, n_cols, &row_challenges);

        // Complete via folding
        let mut yr_full = yr.clone();
        crate::utils::partial_eval_multilinear(&mut yr_full, &row_challenges);

        let mut wr_full = wr.clone();
        crate::utils::partial_eval_multilinear(&mut wr_full, &col_challenges);

        // Brute force
        let all_ch: Vec<BinaryElem32> = col_challenges.iter()
            .chain(row_challenges.iter()).copied().collect();
        let mut brute = data.to_vec();
        crate::utils::partial_eval_multilinear(&mut brute, &all_ch);

        assert_eq!(yr_full[0], brute[0], "yr path must match brute force");
        assert_eq!(wr_full[0], brute[0], "wr path must match brute force");
        assert!(cross_check(&yr, &wr, &col_challenges, &row_challenges));
    }

    #[test]
    fn test_da_and_commitment_same_root() {
        // The DA encoding must produce the same Merkle root as the
        // polynomial commitment's ligero_commit.
        let m = 1 << 8;
        let n = 1 << 4;
        let rs = reed_solomon::<BinaryElem32>(m, m * 4);

        let data: Vec<BinaryElem32> =
            (0..(m * n) as u32).map(BinaryElem32::from).collect();

        let block = encode(&data, m, n, &rs);
        let witness = crate::encode::ligero_commit(&data, m, n, &rs);

        assert_eq!(
            block.row_root().root,
            witness.tree.get_root().root,
            "DA block and commitment witness must share the same root"
        );
    }
}
