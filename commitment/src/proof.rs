//! Proof data structures for the Ligerito commitment scheme.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryFieldElement;
use crate::merkle::{BatchedMerkleProof, MerkleRoot};
use crate::sumcheck::eval::EvalSumcheckRound;

/// Recursive Ligero witness (prover-side only).
///
/// The matrix is stored column-major in a flat buffer for cache-friendly
/// RS encoding. Column `j` occupies `data[j * rows .. (j+1) * rows]`.
pub struct Witness<T: BinaryFieldElement> {
    /// Column-major flat buffer.
    pub data: Vec<T>,
    /// Number of rows (= m * inv_rate).
    pub rows: usize,
    /// Number of columns.
    pub cols: usize,
    /// Merkle tree over hashed rows.
    pub tree: crate::merkle::CompleteMerkleTree,
}

impl<T: BinaryFieldElement> Witness<T> {
    /// Gather row `i` into a new Vec.
    #[inline]
    pub fn gather_row(&self, i: usize) -> Vec<T> {
        let mut row = vec![T::zero(); self.cols];
        for j in 0..self.cols {
            row[j] = self.data[j * self.rows + i];
        }
        row
    }

    /// Number of rows in the matrix.
    #[inline]
    pub fn num_rows(&self) -> usize {
        self.rows
    }
}

/// Merkle root commitment.
#[derive(Clone, Debug)]
pub struct Commitment {
    pub root: MerkleRoot,
}

impl Commitment {
    pub fn size_of(&self) -> usize {
        self.root.size_of()
    }
}

/// Opened rows with Merkle inclusion proof.
#[derive(Clone, Debug)]
pub struct Opening<T: BinaryFieldElement> {
    pub opened_rows: Vec<Vec<T>>,
    pub merkle_proof: BatchedMerkleProof,
}

impl<T: BinaryFieldElement> Opening<T> {
    pub fn size_of(&self) -> usize {
        self.opened_rows
            .iter()
            .map(|row| row.len() * core::mem::size_of::<T>())
            .sum::<usize>()
            + self.merkle_proof.size_of()
    }
}

/// Final round proof data.
#[derive(Clone, Debug)]
pub struct FinalOpening<T: BinaryFieldElement> {
    /// Folded polynomial.
    pub yr: Vec<T>,
    pub opened_rows: Vec<Vec<T>>,
    pub merkle_proof: BatchedMerkleProof,
}

impl<T: BinaryFieldElement> FinalOpening<T> {
    pub fn size_of(&self) -> usize {
        self.yr.len() * core::mem::size_of::<T>()
            + self
                .opened_rows
                .iter()
                .map(|row| row.len() * core::mem::size_of::<T>())
                .sum::<usize>()
            + self.merkle_proof.size_of()
    }
}

/// Sumcheck round coefficients.
#[derive(Clone, Debug)]
pub struct SumcheckRounds<T: BinaryFieldElement> {
    pub transcript: Vec<(T, T, T)>,
}

impl<T: BinaryFieldElement> SumcheckRounds<T> {
    pub fn size_of(&self) -> usize {
        self.transcript.len() * 3 * core::mem::size_of::<T>()
    }
}

/// Complete Ligerito proof.
#[derive(Clone, Debug)]
pub struct Proof<T: BinaryFieldElement, U: BinaryFieldElement> {
    /// Initial commitment (base field).
    pub initial_commitment: Commitment,
    /// Initial opening (base field rows).
    pub initial_opening: Opening<T>,
    /// Recursive round commitments (extension field).
    pub recursive_commitments: Vec<Commitment>,
    /// Recursive round openings (extension field).
    pub recursive_openings: Vec<Opening<U>>,
    /// Final round opening.
    pub final_opening: FinalOpening<U>,
    /// Sumcheck round data.
    pub sumcheck_rounds: SumcheckRounds<U>,
    /// Evaluation sumcheck rounds (empty when no eval claims).
    pub eval_rounds: Vec<EvalSumcheckRound<U>>,
}

impl<T: BinaryFieldElement, U: BinaryFieldElement> Proof<T, U> {
    /// Total byte size of the proof.
    pub fn size_of(&self) -> usize {
        self.initial_commitment.size_of()
            + self.initial_opening.size_of()
            + self
                .recursive_commitments
                .iter()
                .map(|c| c.size_of())
                .sum::<usize>()
            + self
                .recursive_openings
                .iter()
                .map(|p| p.size_of())
                .sum::<usize>()
            + self.final_opening.size_of()
            + self.sumcheck_rounds.size_of()
            + self.eval_rounds.len() * 3 * core::mem::size_of::<U>()
    }
}

/// Builder for constructing proofs incrementally.
pub(crate) struct ProofBuilder<T: BinaryFieldElement, U: BinaryFieldElement> {
    pub initial_commitment: Option<Commitment>,
    pub initial_opening: Option<Opening<T>>,
    pub recursive_commitments: Vec<Commitment>,
    pub recursive_openings: Vec<Opening<U>>,
    pub final_opening: Option<FinalOpening<U>>,
    pub sumcheck_rounds: Option<SumcheckRounds<U>>,
    pub eval_rounds: Vec<EvalSumcheckRound<U>>,
}

impl<T: BinaryFieldElement, U: BinaryFieldElement> ProofBuilder<T, U> {
    pub fn new() -> Self {
        Self {
            initial_commitment: None,
            initial_opening: None,
            recursive_commitments: Vec::new(),
            recursive_openings: Vec::new(),
            final_opening: None,
            sumcheck_rounds: None,
            eval_rounds: Vec::new(),
        }
    }

    /// Finalize into a complete proof.
    pub fn build(self) -> crate::Result<Proof<T, U>> {
        Ok(Proof {
            initial_commitment: self
                .initial_commitment
                .ok_or(crate::Error::InvalidProof)?,
            initial_opening: self.initial_opening.ok_or(crate::Error::InvalidProof)?,
            recursive_commitments: self.recursive_commitments,
            recursive_openings: self.recursive_openings,
            final_opening: self.final_opening.ok_or(crate::Error::InvalidProof)?,
            sumcheck_rounds: self.sumcheck_rounds.ok_or(crate::Error::InvalidProof)?,
            eval_rounds: self.eval_rounds,
        })
    }
}
