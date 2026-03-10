//! This module implements the [ZODA](https://eprint.iacr.org/2025/034) coding scheme.
//!
//! At a high level, the scheme works like any other coding scheme: you start with
//! a piece of data, and split it into shards, and a commitment. Each shard can
//! be checked to belong to the commitment, and, given enough shards, the data can
//! be reconstructed.
//!
//! What makes ZODA interesting is that upon receiving and checking one shard,
//! you become convinced that there exists an original piece of data that will
//! be reconstructable given enough shards. This fails in the case of, e.g.,
//! plain Reed-Solomon coding. For example, if you give people random shards,
//! instead of actually encoding data, then when they attempt to reconstruct the
//! data, they can come to different results depending on which shards they use.
//!
//! Ultimately, this stems from the fact that you can't know if your shard comes
//! from a valid encoding of the data until you have enough shards to reconstruct
//! the data. With ZODA, you know that the shard comes from a valid encoding as
//! soon as you've checked it.
//!
//! # Variant
//!
//! ZODA supports different configurations based on the coding scheme you use
//! for sharding data, and for checking it.
//!
//! We use the Reed-Solomon and Hadamard variant of ZODA: in essence, this means
//! that the shards are Reed-Solomon encoded, and we include additional checksum
//! data which does not help reconstruct the data.
//!
//! ## Deviations
//!
//! In the paper, a sample consists of rows chosen at random from the encoding of
//! the data. With multiple participants receiving samples, they might receive
//! overlapping samples, which we don't want. Instead, we shuffle the rows of
//! the encoded data, and each participant receives a different segment.
//! From that participant's perspective, they've received a completely random
//! choice of rows. The other participants' rows are less random, since they're
//! guaranteed to not overlap. However, no guarantee on the randomness of the other
//! rows is required: each sample is large enough to guarantee that the data
//! has been validly encoded.
//!
//! We also use a Fiat-Shamir transform to make all randomness sampled
//! non-interactively, based on the commitment to the encoded data.
//!
//! # Protocol
//!
//! Let n denote the minimum number of shards needed to recover the data.
//! Let k denote the number of extra shards to generate.
//!
//! We consider the data as being an array of elements in a field F, of 64 bits.
//!
//! Given n and k, we have a certain number of required samples R.
//! We can split these into row samples S, and column samples S',
//! such that S * S' = R.
//!
//! Given a choice of S, our data will need to be arranged into a matrix of size
//!
//!   n S x c
//!
//! with c being >= 1.
//!
//! We choose S as close to R as possible without padding the data. We then
//! choose S' so that S * S' >= R.
//!
//! We also then double S', because the field over which we compute checksums
//! only has 64 bits. This effectively makes the checksum calculated over the
//! extension field F^2. Because we don't actually need to multiply elements
//! in F^2 together, but only ever take linear combinations with elements in F,
//! we can effectively compute over the larger field simply by using 2 "virtual"
//! checksum columns per required column.
//!
//! For technical reasons, the encoded data will have not have (n + k) S rows,
//! but pad((n + k) S) rows, where pad returns the next power of two.
//! This is to our advantage, in that given n shards, we will be able to reconstruct
//! the data, but these shards consists of rows sampled at random from
//! pad((n + k) S) rows, thus requiring fewer samples.
//!
//! ## Encoding
//!
//! 1. The data is arranged as a matrix X of size n S x c.
//! 2. The data is Reed-Solomon encoded, turning it into a matrix X' of size pad((n + k) S) x c.
//! 3. The rows of X' are committed to using a vector commitment V (concretely, a Merkle Tree).
//! 4. V, along with the size of the data, in bytes, are committed to, producing Com.
//! 5. Com is hashed to create randomness, first to generate a matrix H of size c x S',
//!    and then to shuffle the rows of X'.
//! 6. Z := X H, a matrix of size n S x S' is computed.
//! 7. The ith shard (starting from 0) then consists of:
//!    - the size of the data, in bytes,
//!    - the vector commitment, V,
//!    - the checksum Z,
//!    - rows i * S..(i + 1) * S of Y, along with a proof of inclusion in V, at the original index.
//!
//! ## Checking
//!
//! Let A_{S} denote the matrix formed by taking the rows in a given subset S.
//!
//! 1. Check that Com is the hash of V and the size of the data, in bytes.
//! 2. Use Com to compute H of size c x S', and figure recompute the ith row sample S_i.
//! 3. Check that Z is of size n S x S'.
//! 4. Encode Z to get Z', a matrix of size pad((n + k) S) x S'.
//!
//! These steps now depend on the particular shard.
//!
//! 5. Check that X'_{S_i} (the shard's data) is a matrix of size S x c.
//! 6. Use the inclusion proofs to check that each row of X'_{S_i} is included in V,
//!    at the correct index.
//! 7. Check that X'_{S_i} H = Z'_{S_i}
//!
//! ## Decoding
//!
//! 1. Given n checked shards, you have n S encoded rows, which can be Reed-Solomon decoded.

use crate::{Config, ValidatingScheme};
use bytes::BufMut;
use commonware_codec::{Encode, EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    transcript::{Summary, Transcript},
    Digest, Hasher,
};
use commonware_math::{
    fields::goldilocks::F,
    ntt::{EvaluationVector, Matrix},
};
use commonware_parallel::Strategy;
use commonware_storage::bmt::{Builder as BmtBuilder, Error as BmtError, Proof};
use rand::seq::SliceRandom as _;
use std::{marker::PhantomData, sync::Arc};
use thiserror::Error;

mod phased_scheme;
mod scheme;
mod topology;
use topology::Topology;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid shard")]
    InvalidShard,
    #[error("invalid index {0}")]
    InvalidIndex(u16),
    #[error("insufficient shards {0} < {1}")]
    InsufficientShards(usize, usize),
    #[error("insufficient unique rows {0} < {1}")]
    InsufficientUniqueRows(usize, usize),
    #[error("checked shard commitment does not match decode commitment")]
    InconsistentCheckedShard,
    #[error("failed to create inclusion proof: {0}")]
    FailedToCreateInclusionProof(BmtError),
}

const NAMESPACE: &[u8] = b"_COMMONWARE_CODING_ZODA";

#[derive(Clone, Copy)]
pub struct Zoda<H> {
    _marker: PhantomData<H>,
}

impl<H> std::fmt::Debug for Zoda<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Zoda")
    }
}

impl<H: Hasher> ValidatingScheme for Zoda<H> {}

/// A shard of data produced by the encoding scheme.
#[derive(Clone, Debug)]
pub struct Shard<D: Digest> {
    data_bytes: usize,
    root: D,
    inclusion_proof: Proof<D>,
    rows: Arc<Matrix<F>>,
    checksum: Arc<Matrix<F>>,
}

impl<D: Digest> PartialEq for Shard<D> {
    fn eq(&self, other: &Self) -> bool {
        self.data_bytes == other.data_bytes
            && self.root == other.root
            && self.inclusion_proof == other.inclusion_proof
            && self.rows == other.rows
            && self.checksum == other.checksum
    }
}

impl<D: Digest> Eq for Shard<D> {}

impl<D: Digest> EncodeSize for Shard<D> {
    fn encode_size(&self) -> usize {
        self.data_bytes.encode_size()
            + self.root.encode_size()
            + self.inclusion_proof.encode_size()
            + self.rows.as_ref().encode_size()
            + self.checksum.encode_size()
    }
}

impl<D: Digest> Write for Shard<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.data_bytes.write(buf);
        self.root.write(buf);
        self.inclusion_proof.write(buf);
        self.rows.as_ref().write(buf);
        self.checksum.write(buf);
    }
}

impl<D: Digest> Read for Shard<D> {
    type Cfg = crate::CodecConfig;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let data_bytes = usize::read_cfg(buf, &RangeCfg::from(..=cfg.maximum_shard_size))?;
        let max_els = cfg.maximum_shard_size / F::SIZE;
        Ok(Self {
            data_bytes,
            root: ReadExt::read(buf)?,
            inclusion_proof: Read::read_cfg(buf, &max_els)?,
            rows: Arc::new(Read::read_cfg(buf, &(max_els, ()))?),
            checksum: Arc::new(Read::read_cfg(buf, &(max_els, ()))?),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Shard<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            data_bytes: u.arbitrary::<u32>()? as usize,
            root: u.arbitrary()?,
            inclusion_proof: u.arbitrary()?,
            rows: Arc::new(u.arbitrary()?),
            checksum: Arc::new(u.arbitrary()?),
        })
    }
}

/// Take indices up to `total`, and shuffle them.
///
/// The shuffle depends, deterministically, on the transcript.
///
/// # Panics
///
/// Panics if `total` exceeds `u32::MAX`.
fn shuffle_indices(transcript: &Transcript, total: usize) -> Vec<u32> {
    let total: u32 = total
        .try_into()
        .expect("encoded_rows exceeds u32::MAX; data too large for ZODA");
    let mut out = (0..total).collect::<Vec<_>>();
    out.shuffle(&mut transcript.noise(b"shuffle"));
    out
}

/// Create a checking matrix of the right shape.
///
/// This matrix is random, using the transcript as a deterministic source of randomness.
fn checking_matrix(transcript: &Transcript, topology: &Topology) -> Matrix<F> {
    Matrix::rand(
        &mut transcript.noise(b"checking matrix"),
        topology.data_cols,
        topology.column_samples,
    )
}

#[derive(Clone)]
struct CheckingCore<D: Digest> {
    commitment: Summary,
    topology: Topology,
    root: D,
    checking_matrix: Matrix<F>,
    encoded_checksum: Matrix<F>,
    shuffled_indices: Vec<u32>,
}

impl<D: Digest> CheckingCore<D> {
    fn reckon(
        config: &Config,
        commitment: &Summary,
        data_bytes: usize,
        root: D,
        checksum: &Matrix<F>,
    ) -> Result<Self, Error> {
        let topology = Topology::reckon(config, data_bytes);
        let mut transcript = Transcript::new(NAMESPACE);
        transcript.commit((topology.data_bytes as u64).encode());
        transcript.commit(root.encode());
        let expected_commitment = transcript.summarize();
        if *commitment != expected_commitment {
            return Err(Error::InvalidShard);
        }
        let mut transcript = Transcript::resume(expected_commitment);
        let checking_matrix = checking_matrix(&transcript, &topology);
        if checksum.rows() != topology.data_rows || checksum.cols() != topology.column_samples {
            return Err(Error::InvalidShard);
        }
        // Commit to the checksum before generating the indices to check.
        //
        // Nota bene: `checksum.encode()` is *serializing* the checksum, not
        // Reed-Solomon encoding it.
        //
        // cf. the implementation of `Scheme::encode` for ZODA for why it's important
        // that we do Reed-Solomon encoding of the checksum ourselves.
        transcript.commit(checksum.encode());
        let encoded_checksum = checksum
            .as_polynomials(topology.encoded_rows)
            .expect("checksum has too many rows")
            .evaluate()
            .data();
        let shuffled_indices = shuffle_indices(&transcript, topology.encoded_rows);

        Ok(Self {
            commitment: expected_commitment,
            topology,
            root,
            checking_matrix,
            encoded_checksum,
            shuffled_indices,
        })
    }

    fn check_rows<H: Hasher<Digest = D>>(
        &self,
        index: u16,
        inclusion_proof: &Proof<D>,
        rows: &Matrix<F>,
    ) -> Result<usize, Error> {
        self.topology.check_index(index)?;
        if rows.rows() != self.topology.samples || rows.cols() != self.topology.data_cols {
            return Err(Error::InvalidShard);
        }
        let shard_idx = index as usize;
        let these_shuffled_indices = &self.shuffled_indices
            [shard_idx * self.topology.samples..(shard_idx + 1) * self.topology.samples];

        let proof_elements: Vec<(H::Digest, u32)> = these_shuffled_indices
            .iter()
            .zip(rows.iter())
            .map(|(&i, row)| (row_digest::<H>(row), i))
            .collect();

        let mut hasher = H::new();
        if inclusion_proof
            .verify_multi_inclusion(&mut hasher, &proof_elements, &self.root)
            .is_err()
        {
            return Err(Error::InvalidShard);
        }

        let shard_checksum = rows.mul(&self.checking_matrix);
        for (row, &i) in shard_checksum.iter().zip(these_shuffled_indices) {
            if row != &self.encoded_checksum[i as usize] {
                return Err(Error::InvalidShard);
            }
        }
        Ok(shard_idx)
    }
}

trait CheckedShardView {
    fn index(&self) -> usize;
    fn shard(&self) -> &Matrix<F>;
}

fn decode_checked_shards<D: Digest, S: CheckedShardView>(
    core: &CheckingCore<D>,
    shards: &[S],
) -> Result<Vec<u8>, Error> {
    let Topology {
        encoded_rows,
        data_cols,
        data_rows,
        data_bytes,
        min_shards,
        samples,
        ..
    } = core.topology;
    if shards.len() < min_shards {
        return Err(Error::InsufficientShards(shards.len(), min_shards));
    }
    let mut evaluation = EvaluationVector::<F>::empty(encoded_rows.ilog2() as usize, data_cols);
    for shard in shards {
        let indices =
            &core.shuffled_indices[shard.index() * samples..(shard.index() + 1) * samples];
        for (&i, row) in indices.iter().zip(shard.shard().iter()) {
            evaluation.fill_row(u64::from(i) as usize, row);
        }
    }
    // This should never happen, because we check each shard, and the shards
    // should have distinct rows. But, as a sanity check, this doesn't hurt.
    let filled_rows = evaluation.filled_rows();
    if filled_rows < data_rows {
        return Err(Error::InsufficientUniqueRows(filled_rows, data_rows));
    }
    Ok(collect_u64_le(
        data_bytes,
        F::stream_to_u64s(
            evaluation
                .recover()
                .coefficients_up_to(data_rows)
                .flatten()
                .copied(),
        ),
    ))
}

/// Create an iterator over the data of a buffer, interpreted as little-endian u64s.
fn iter_u64_le(data: impl bytes::Buf) -> impl Iterator<Item = u64> {
    struct Iter<B> {
        remaining_u64s: usize,
        tail: usize,
        inner: B,
    }

    impl<B: bytes::Buf> Iter<B> {
        fn new(inner: B) -> Self {
            let remaining_u64s = inner.remaining() / 8;
            let tail = inner.remaining() % 8;
            Self {
                remaining_u64s,
                tail,
                inner,
            }
        }
    }

    impl<B: bytes::Buf> Iterator for Iter<B> {
        type Item = u64;

        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining_u64s > 0 {
                self.remaining_u64s -= 1;
                return Some(self.inner.get_u64_le());
            }
            if self.tail > 0 {
                let mut chunk = [0u8; 8];
                self.inner.copy_to_slice(&mut chunk[..self.tail]);
                self.tail = 0;
                return Some(u64::from_le_bytes(chunk));
            }
            None
        }
    }
    Iter::new(data)
}

fn collect_u64_le(max_length: usize, data: impl Iterator<Item = u64>) -> Vec<u8> {
    let mut out = Vec::with_capacity(max_length);
    for d in data {
        out.extend_from_slice(&d.to_le_bytes());
    }
    out.truncate(max_length);
    out
}

fn row_digest<H: Hasher>(row: &[F]) -> H::Digest {
    let mut h = H::new();
    for x in row {
        h.update(&x.to_le_bytes());
    }
    h.finalize()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "arbitrary")]
    mod conformance {
        use crate::zoda::Shard;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<Shard<Sha256Digest>>,
        }
    }
}
