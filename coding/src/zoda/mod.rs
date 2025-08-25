//! A ZODA (Zero-Overhead Data Availability) protocol implementation.
//!
//! # Protocol Overview
//!
//! ## [`Commitment`] construction
//!
//! ```text
//! 1. Parse and pack the data into fields within a square matrix `X_tilde`.
//!                                ┌─────┬─────┐
//!  ┌─────┬─────┬─────┬─────┐     │  A  │  B  │
//!  │  A  │  B  │  C  │  D  ├────►├─────┼─────┤
//!  └─────┴─────┴─────┴─────┘     │  C  │  D  │
//!                                └─────┴─────┘
//!
//! 2. Reed-Solomon encode the columns of `X_tilde`, producing recovery shards.
//! ┌─────┬─────┐
//! │  A  │  B  │
//! ├─────┼─────┤
//! │  C  │  D  │
//! ├─────┼─────┤
//! │  A' │  B' │
//! ├─────┼─────┤
//! │  C' │  D' │
//! └─────┴─────┘
//!
//! 3. Reed-Solomon encode the columns of the intermediate matrix, producing more recovery shards.
//! ┌─────┬─────┬─────┬─────┐
//! │  A  │  B  │  A' │  B' │
//! ├─────┼─────┼─────┼─────┤
//! │  C  │  D  │  C' │  D' │
//! ├─────┼─────┼─────┼─────┤
//! │  A' │  B' │ A'' │ B'' │
//! ├─────┼─────┼─────┼─────┤
//! │  C' │  D' │ C'' │ D'' │
//! └─────┴─────┴─────┴─────┘
//!
//! 4. Generate two merkle trees, one for the rows and one for the columns of the final matrix `X`.
//!
//!                           ┌────────┐
//!                  ┌────────┤col_root├────────┐
//!                  │        └────────┘        │
//!              ┌───┴────┐                 ┌───┴────┐
//!              │H(c1,c2)│                 │H(c1,c2)│
//!              └┬──────┬┘                 └┬──────┬┘
//!               │      │                   │      │
//!       ┌───────┴─┐ ┌──┴──────┐ ┌──────────┴──┐ ┌─┴───────────┐
//!       │A,C,A',C'│ │B,D,B',D'│ │A',C',A'',C''│ │B',D',B'',D''│
//!       └─────────┘ └─────────┘ └─────────────┘ └─────────────┘
//!
//!                           ┌────────┐
//!                  ┌────────┤row_root├────────┐
//!                  │        └────────┘        │
//!              ┌───┴────┐                 ┌───┴────┐
//!              │H(c1,c2)│                 │H(c1,c2)│
//!              └┬──────┬┘                 └┬──────┬┘
//!               │      │                   │      │
//!       ┌───────┴─┐ ┌──┴──────┐ ┌──────────┴──┐ ┌─┴───────────┐
//!       │A,b,A',B'│ │C,D,C',D'│ │A',B',A'',B''│ │C',D',C'',D''│
//!       └─────────┘ └─────────┘ └─────────────┘ └─────────────┘
//! ```
//!
//! ## Creating a [`Sample`]
//!
//! ```text
//! 1. Randomly sample some rows and columns from `X`. To reconstruct the original data, at least half
//!    the rows and half the columns of `X` must be sampled.
//!
//!                     │     │
//!                     ▼     ▼
//!      ┌─────┬─────┬─────┬─────┐
//!      │  A  │  B  │  A' │  B' │
//!      ├─────┼─────┼─────┼─────┤
//!  ───►│  C  │  D  │  C' │  D' │
//!      ├─────┼─────┼─────┼─────┤
//!  ───►│  A' │  B' │ A'' │ B'' │
//!      ├─────┼─────┼─────┼─────┤
//!      │  C' │  D' │ C'' │ D'' │
//!      └─────┴─────┴─────┴─────┘
//!
//! 2. For each sampled row and column, provide the contents and a merkle proof of inclusion.
//! ```
//!
//! ## Verification
//!
//! Verification of a [`Sample`] and [`EncodingProof`] entails:
//! 1. For each sampled row, multiply by the randomness vector `r` and check that the result matches the corresponding
//!    element in `y_r` from the encoding proof.
//! 2. For each sampled column, multiply by the randomness vector `r'` and check that the result matches the corresponding
//!    element in `w_r'` from the encoding proof.
//! 3. Verifying the merkle proofs for each sampled row and column.
//!
//! # Usage
//!
//! ```rust
//! use commonware_coding::zoda::*;
//! use commonware_cryptography::Blake3;
//! use rand::{Rng, RngCore};
//!
//! const SIZE: usize = 2usize.pow(12);
//! const RATE_INVERSE: usize = 4;
//!
//! let hasher = &mut Blake3::default();
//! let mut rand = rand::thread_rng();
//!
//! // Create a commitment over some random data.
//! let mut data = vec![0u8; SIZE];
//! rand.fill_bytes(&mut data);
//! let commitment = Commitment::<_, GF32>::create(&data, hasher, RATE_INVERSE).unwrap();
//!
//! // Generate a mock random vector (usually through fiat-shamir.)
//! let mut r = vec![0u8; commitment.x_tilde.rows()];
//! rand.fill_bytes(r.as_mut_slice());
//! let r = r.into_iter().map(|b| (b as u32).into()).collect::<Vec<_>>();
//! let r_prime = r.clone();
//!
//! // Generate the encoding proof.
//! let enc_proof = commitment.encoding_proof(&r, &r_prime);
//!
//! // Sample some rows and columns.
//! let row_samples = (0..commitment.x_tilde.rows())
//!     .map(|_| rand.gen_range(0..commitment.x.rows()))
//!     .collect::<Vec<_>>();
//! let col_samples = (0..commitment.x_tilde.cols())
//!     .map(|_| rand.gen_range(0..commitment.x.cols()))
//!     .collect::<Vec<_>>();
//! let sample = commitment.sample(&row_samples, &col_samples).unwrap();
//!
//! // Verify the integrity of the samples.
//! verify(hasher, &sample, &enc_proof, &r, &r_prime, RATE_INVERSE).unwrap();
//! ```
//!
//! # Acknowledgements
//!
//! The following resources were used as references when implementing this crate:
//!
//! - [_ZODA: Zero-Overhead Data Availability_](https://eprint.iacr.org/2025/034.pdf)
//! - <https://baincapitalcrypto.com/zoda-explainer/>
//! - <https://github.com/angeris/zoda-livestream>

use commonware_codec::{Encode, EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::Hasher;
use commonware_storage::bmt::{
    Builder as TreeBuilder, Error as TreeError, Proof as TreeProof, Tree,
};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use reed_solomon_simd::{Error as RSError, ReedSolomonEncoder};
use std::collections::HashMap;
use thiserror::Error;

mod field;
pub use field::{BinaryField, FieldVector, GF128, GF32};

mod data_square;
pub use data_square::DataSquare;

/// An error that can occur during operations on a [`Commitment`].
#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error(transparent)]
    ReedSolomon(#[from] RSError),

    #[error(transparent)]
    MerkleTree(#[from] TreeError),

    #[error("Index out of bounds: {0}")]
    IndexOutOfBounds(usize),

    #[error("Reed-Solomon rate inverse must be at least 2. Got rate: 1/{0}")]
    InvalidRate(usize),
}

/// An error that can occur during verification of a [`Sample`].
#[derive(Error, Debug)]
pub enum VerificationError {
    #[error(transparent)]
    ReedSolomon(#[from] RSError),

    #[error(transparent)]
    MerkleTree(#[from] TreeError),

    #[error("Encoding proof is invalid")]
    EncodingProofInvalid,
}

/// A ZODA commitment over arbitrary data.
#[derive(Debug, Clone)]
pub struct Commitment<H, F>
where
    H: Hasher,
    F: BinaryField,
{
    /// `X_tilde` is the original data square.
    pub x_tilde: DataSquare<F>,

    /// `X` is the final "Extended Data Square," with doubly Reed-Solomon encoded rows and columns.
    pub x: DataSquare<F>,

    /// A [`Tree`] of all the rows in `X`. Leaves commit to the encoded rows.
    ///
    /// ## Invariants
    /// - The tree has the same number of leaves as the number of rows in `X`.
    pub row_tree: Tree<H>,

    /// A [`Tree`] of all the columns in `X`. Leaves commit to the encoded columns.
    ///
    /// ## Invariants
    /// - The tree has the same number of leaves as the number of columns in `X`.
    pub col_tree: Tree<H>,
}

impl<H, F> Commitment<H, F>
where
    H: Hasher,
    F: BinaryField,
    for<'a> &'a F: Encode,
{
    /// Constructs a new [`Commitment`] from the given data.
    ///
    /// The `rate_inverse` parameter determines the redundancy of the Reed-Solomon encoding.
    /// This value directly affects the size of the proof. See [`Self::sample`] documentation.
    pub fn create<E: Encode>(
        obj: &E,
        hasher: &mut H,
        rate_inverse: usize,
    ) -> Result<Self, CommitmentError> {
        if rate_inverse < 2 {
            return Err(CommitmentError::InvalidRate(rate_inverse));
        }

        let (packed, size) = Self::pack(obj);
        let x_tilde = DataSquare::new(packed, size, size);

        // Encode the columns of the packed data.
        let col_parity = Self::encode_lanes(x_tilde.partial_par_rows_iter(), size, rate_inverse)?;

        // Construct an intermediate row-major (rate_inverse * size) x size matrix, from the original data and the
        // column parity.
        let x_cols = {
            let col_parity_rows =
                (0..size).map(|i| col_parity.iter().flatten().skip(i).step_by(size));
            let rows = x_tilde
                .rows_iter()
                .flatten()
                .chain(col_parity_rows.flatten())
                .copied()
                .collect::<Vec<_>>();
            DataSquare::new(rows, size * rate_inverse, size)
        };

        // Encode the rows of `X_cols`.
        let row_parity = Self::encode_lanes(x_cols.partial_par_rows_iter(), size, rate_inverse)?;

        // Construct the final (rate_inverse * size) x (rate_inverse * size) matrix `X`, from `X_cols`
        // and the row parity.
        let x_rows = x_cols
            .partial_par_rows_iter()
            .enumerate()
            .flat_map(|(i, row)| row.chain(row_parity[i].iter()).copied().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let x = DataSquare::new(x_rows, size * rate_inverse, size * rate_inverse);

        // Merkleize the rows and columns of `X` in parallel.
        let hasher_b = &mut hasher.clone();
        let (row_tree, col_tree) = rayon::join(
            || {
                Self::merkleize(
                    x.rows_iter().map(|r| r.collect::<Vec<_>>()),
                    x.rows(),
                    hasher,
                )
            },
            || {
                Self::merkleize(
                    x.cols_iter().map(|c| c.collect::<Vec<_>>()),
                    x.cols(),
                    hasher_b,
                )
            },
        );

        Ok(Self {
            x_tilde,
            x,
            row_tree,
            col_tree,
        })
    }

    /// Returns the root hash of the row tree.
    pub fn row_root(&self) -> H::Digest {
        self.row_tree.root()
    }

    /// Returns the root hash of the column tree.
    pub fn col_root(&self) -> H::Digest {
        self.col_tree.root()
    }

    /// Creates a new [`EncodingProof`] from random vectors `r` and `r'`.
    pub fn encoding_proof(&self, r: &[F], r_prime: &[F]) -> EncodingProof<F> {
        let y_r = &self.x * r;
        let w_r_prime = &self.x.transpose() * r_prime;

        EncodingProof { y_r, w_r_prime }
    }

    /// Creates a new [`Sample`] from the given sampled row and column indices.
    ///
    /// To have a reasonable assumption that the data is correctly encoded and that the samples
    /// are correct, at least `min_samples` rows and columns should be sampled, where
    /// `min_samples = ceil(-bits_of_security / log_2(1 − (1 - rate) / 2))`
    pub fn sample(
        &self,
        row_indices: &[usize],
        col_indices: &[usize],
    ) -> Result<Sample<H, F>, CommitmentError> {
        let rows = row_indices
            .par_iter()
            .map(|&i| {
                let row_contents = self
                    .x
                    .row_iter(i)
                    .ok_or(CommitmentError::IndexOutOfBounds(i))?
                    .copied()
                    .collect::<Vec<_>>();
                let row_proof = self.row_tree.proof(i as u32)?;
                Ok((i, (row_contents, row_proof)))
            })
            .collect::<Result<_, CommitmentError>>()?;
        let cols = col_indices
            .par_iter()
            .map(|&i| {
                let col_contents = self
                    .x
                    .col_iter(i)
                    .ok_or(CommitmentError::IndexOutOfBounds(i))?
                    .copied()
                    .collect::<Vec<_>>();
                let col_proof = self.col_tree.proof(i as u32)?;
                Ok((i, (col_contents, col_proof)))
            })
            .collect::<Result<_, CommitmentError>>()?;

        Ok(Sample {
            row_root: self.row_tree.root(),
            col_root: self.col_tree.root(),
            rows,
            cols,
        })
    }

    /// Packs an encodable object into field elements (`F`).
    ///
    /// If the data doesn't fit into a square, it is padded with zeros.
    fn pack<E: Encode>(obj: &E) -> (Vec<F>, usize) {
        let encoded = obj.encode();

        let mut packed = encoded
            .chunks(F::BYTE_SIZE)
            .map(F::from_le_bytes)
            .collect::<Vec<_>>();

        // Resize to a full square if necessary.
        let size = (packed.len() as f64).sqrt().ceil() as usize;
        if packed.len() < size * size {
            packed.resize(size * size, F::ZERO);
        }

        (packed, size)
    }

    /// Reed-solomon encodes several lanes of data in parallel, producing an ordered set
    /// of recovery shards for each lane.
    fn encode_lanes<'a>(
        lanes: impl IndexedParallelIterator<Item = impl Iterator<Item = &'a F>>,
        shard_size: usize,
        rate_inverse: usize,
    ) -> Result<Vec<Vec<F>>, RSError>
    where
        F: 'a,
    {
        lanes
            .map(|mut lane| {
                // Add each lane element as an original shard. (RS rate: 1/rate_inverse)
                let mut encoder = ReedSolomonEncoder::new(
                    shard_size,
                    shard_size * rate_inverse.saturating_sub(1),
                    F::BYTE_SIZE,
                )?;
                lane.try_for_each(|el| encoder.add_original_shard(el.to_le_bytes()))?;

                // Encode the lane and return the parity shards.
                let result = encoder.encode()?;
                let recovery_shards = result
                    .recovery_iter()
                    .map(F::from_le_bytes)
                    .collect::<Vec<_>>();
                Ok(recovery_shards)
            })
            .collect::<Result<Vec<_>, RSError>>()
    }

    /// Creates a [`Tree`] from the given elements.
    fn merkleize<E: Encode>(
        leaves: impl Iterator<Item = E>,
        leaf_count: usize,
        hasher: &mut H,
    ) -> Tree<H> {
        let mut tree = TreeBuilder::<H>::new(leaf_count);

        // Include each encoded item's hash as a leaf in the tree.
        leaves.for_each(|v| {
            hasher.update(v.encode().as_ref());
            tree.add(&hasher.finalize());
        });

        tree.build()
    }
}

/// A proof that the encoding for a certain [`Commitment`] was performed correctly.
#[derive(Debug, Clone)]
pub struct EncodingProof<F: BinaryField> {
    y_r: Vec<F>,
    w_r_prime: Vec<F>,
}

impl<F: BinaryField> Write for EncodingProof<F> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.y_r.write(buf);
        self.w_r_prime.write(buf);
    }
}

impl<F: BinaryField> EncodeSize for EncodingProof<F> {
    fn encode_size(&self) -> usize {
        self.y_r.encode_size() + self.w_r_prime.encode_size()
    }
}

impl<F: BinaryField<Cfg = ()>> Read for EncodingProof<F> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let range_cfg = RangeCfg::from(0..=usize::MAX);

        let y_r = Vec::<F>::read_cfg(buf, &(range_cfg, ()))?;
        let w_r_prime = Vec::<F>::read_cfg(buf, &(range_cfg, ()))?;

        Ok(Self { y_r, w_r_prime })
    }
}

/// A set of openings for sampled rows and columns in a [`Commitment`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Sample<H: Hasher, F: BinaryField> {
    row_root: H::Digest,
    col_root: H::Digest,
    rows: HashMap<usize, (Vec<F>, TreeProof<H>)>,
    cols: HashMap<usize, (Vec<F>, TreeProof<H>)>,
}

impl<H: Hasher, F: BinaryField> Sample<H, F> {
    /// Returns the indices of sampled rows
    pub fn sampled_row_indices(&self) -> Vec<usize> {
        self.rows.keys().copied().collect::<Vec<_>>()
    }

    /// Returns the indices of sampled columns
    pub fn sampled_col_indices(&self) -> Vec<usize> {
        self.cols.keys().copied().collect::<Vec<_>>()
    }
}

impl<H: Hasher, F: BinaryField> Write for Sample<H, F> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.row_root.write(buf);
        self.col_root.write(buf);

        self.rows.len().write(buf);
        self.rows.iter().for_each(|(idx, (row, proof))| {
            idx.write(buf);
            row.write(buf);
            proof.write(buf);
        });

        self.cols.len().write(buf);
        self.cols.iter().for_each(|(idx, (col, proof))| {
            idx.write(buf);
            col.write(buf);
            proof.write(buf);
        });
    }
}

impl<H: Hasher, F: BinaryField> EncodeSize for Sample<H, F> {
    fn encode_size(&self) -> usize {
        let sample_map_encode_size = |map: &HashMap<usize, (Vec<F>, TreeProof<H>)>| {
            map.iter()
                .fold(map.len().encode_size(), |acc, (idx, (row, proof))| {
                    acc + idx.encode_size() + row.encode_size() + proof.encode_size()
                })
        };

        self.row_root.encode_size()
            + self.col_root.encode_size()
            + sample_map_encode_size(&self.rows)
            + sample_map_encode_size(&self.cols)
    }
}

impl<H: Hasher, F: BinaryField<Cfg = ()>> Read for Sample<H, F> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let row_root = H::Digest::read_cfg(buf, cfg)?;
        let col_root = H::Digest::read_cfg(buf, cfg)?;

        let range_cfg = RangeCfg::from(0..=usize::MAX);

        let row_count = usize::read_cfg(buf, &range_cfg)?;
        let mut rows = HashMap::with_capacity(row_count);
        for _ in 0..row_count {
            let idx = usize::read_cfg(buf, &range_cfg)?;
            let row = Vec::<F>::read_cfg(buf, &(range_cfg, ()))?;
            let proof = TreeProof::<H>::read_cfg(buf, cfg)?;
            rows.insert(idx, (row, proof));
        }

        let col_count = usize::read_cfg(buf, &range_cfg)?;
        let mut cols = HashMap::with_capacity(col_count);
        for _ in 0..col_count {
            let idx = usize::read_cfg(buf, &range_cfg)?;
            let col = Vec::<F>::read_cfg(buf, &(range_cfg, ()))?;
            let proof = TreeProof::<H>::read_cfg(buf, cfg)?;
            cols.insert(idx, (col, proof));
        }

        Ok(Self {
            row_root,
            col_root,
            rows,
            cols,
        })
    }
}

/// Verifies the integrity of an [`EncodingProof`] and [`Sample`].
pub fn verify<H: Hasher, F: BinaryField>(
    hasher: &mut H,
    sample: &Sample<H, F>,
    encoding_proof: &EncodingProof<F>,
    r: &[F],
    r_prime: &[F],
    rate_inverse: usize,
) -> Result<(), VerificationError> {
    // Initially check that the encoding proof is well-formed over the supplied randomness.
    let y_r_r_prime = FieldVector::from(encoding_proof.y_r.as_slice()) * r_prime;
    let w_r_prime_r = FieldVector::from(encoding_proof.w_r_prime.as_slice()) * r;
    if y_r_r_prime != w_r_prime_r {
        return Err(VerificationError::EncodingProofInvalid);
    }

    let mut encoder = ReedSolomonEncoder::new(
        encoding_proof.y_r.len(),
        encoding_proof.y_r.len() * rate_inverse.saturating_sub(1),
        F::BYTE_SIZE,
    )?;

    // Encode `y_r`
    encoding_proof
        .y_r
        .iter()
        .try_for_each(|el| encoder.add_original_shard(el.to_le_bytes()))?;
    let y_r_enc_result = encoder.encode()?;
    let y_r_enc = encoding_proof
        .y_r
        .iter()
        .copied()
        .chain(y_r_enc_result.recovery_iter().map(F::from_le_bytes))
        .collect::<Vec<_>>();

    for (idx, (row, _proof)) in sample.rows.iter() {
        let prod = FieldVector::from(row.as_slice()) * r;
        if prod != y_r_enc[*idx] {
            return Err(VerificationError::EncodingProofInvalid);
        }
    }

    // Drop the encoding result explicitly to reuse the encoder.
    drop(y_r_enc_result);

    // Encode `w_r_prime`
    encoding_proof
        .w_r_prime
        .iter()
        .try_for_each(|el| encoder.add_original_shard(el.to_le_bytes()))?;
    let w_r_prime_enc_result = encoder.encode()?;
    let w_r_prime_enc = encoding_proof
        .w_r_prime
        .iter()
        .copied()
        .chain(w_r_prime_enc_result.recovery_iter().map(F::from_le_bytes))
        .collect::<Vec<_>>();

    for (idx, (col, _proof)) in sample.cols.iter() {
        let prod = FieldVector::from(col.as_slice()) * r_prime;
        if prod != w_r_prime_enc[*idx] {
            return Err(VerificationError::EncodingProofInvalid);
        }
    }

    // Verify the row and column openings in parallel.
    let p_hasher = &mut hasher.clone();
    let (row_res, col_res) = rayon::join(
        || {
            for (row_idx, (row_contents, row_proof)) in &sample.rows {
                let encoded = row_contents.encode();
                hasher.update(encoded.as_ref());
                let leaf_hash = hasher.finalize();

                row_proof.verify(hasher, &leaf_hash, *row_idx as u32, &sample.row_root)?;
            }

            Ok::<_, TreeError>(())
        },
        || {
            for (col_idx, (col_contents, col_proof)) in &sample.cols {
                let encoded = col_contents.encode();
                p_hasher.update(encoded.as_ref());
                let leaf_hash = p_hasher.finalize();

                col_proof.verify(p_hasher, &leaf_hash, *col_idx as u32, &sample.col_root)?;
            }

            Ok::<_, TreeError>(())
        },
    );

    row_res.and(col_res).map_err(VerificationError::MerkleTree)
}

#[cfg(test)]
mod test {
    use super::*;
    use commonware_cryptography::Blake3;
    use rand::{Rng, RngCore};

    #[test]
    fn test_e2e_gf32() {
        const SIZE: usize = 2usize.pow(12);
        const RATE_INVERSE: usize = 4;

        let hasher = &mut Blake3::default();
        let mut rand = rand::thread_rng();

        let mut data = vec![0u8; SIZE];
        rand.fill_bytes(&mut data);
        let commitment = Commitment::<_, GF32>::create(&data, hasher, RATE_INVERSE).unwrap();

        // Generate some randomness (testing; usually through fiat-shamir.)
        let mut r = vec![0u8; commitment.x_tilde.rows()];
        rand.fill_bytes(r.as_mut_slice());
        let r = r.into_iter().map(|b| (b as u32).into()).collect::<Vec<_>>();
        let r_prime = r.clone();

        // Generate the encoding proof.
        let enc_proof = commitment.encoding_proof(&r, &r_prime);

        // Sample some rows and columns.
        let row_samples = (0..commitment.x_tilde.rows())
            .map(|_| rand.gen_range(0..commitment.x.rows()))
            .collect::<Vec<_>>();
        let col_samples = (0..commitment.x_tilde.cols())
            .map(|_| rand.gen_range(0..commitment.x.cols()))
            .collect::<Vec<_>>();
        let sample = commitment.sample(&row_samples, &col_samples).unwrap();

        // Verify the integrity of the samples.
        verify(hasher, &sample, &enc_proof, &r, &r_prime, RATE_INVERSE).unwrap();
    }
}
