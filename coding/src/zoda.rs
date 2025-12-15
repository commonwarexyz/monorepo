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
//! ## Re-Sharding
//!
//! When re-transmitting a shard to other people, only the following are transmitted:
//! - rows i * S..(i + 1) * S of Y, along with the inclusion proofs.
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
use crate::{Config, Scheme, ValidatingScheme};
use bytes::BufMut;
use commonware_codec::{Encode, EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    transcript::{Summary, Transcript},
    Hasher,
};
use commonware_math::{
    fields::goldilocks::F,
    ntt::{EvaluationVector, Matrix},
};
use commonware_storage::mmr::{
    mem::DirtyMmr, verification::multi_proof, Error as MmrError, Location, Proof, StandardHasher,
};
use futures::executor::block_on;
use rand::seq::SliceRandom as _;
use rayon::{iter::ParallelIterator, prelude::IntoParallelIterator, ThreadPoolBuilder};
use std::{marker::PhantomData, sync::Arc};
use thiserror::Error;

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

mod topology {
    use super::Error;
    use crate::Config;
    use commonware_math::fields::goldilocks::F;
    use commonware_utils::BigRationalExt as _;
    use num_rational::BigRational;

    const SECURITY_BITS: usize = 126;
    // Fractional precision for log2 calculations when computing required samples.
    // We use the next power of 2 above SECURITY_BITS (128 = 2^7), which provides
    // 1/128 fractional precision, sufficient for these security calculations.
    const LOG2_PRECISION: usize = SECURITY_BITS.next_power_of_two().trailing_zeros() as usize;

    /// Contains the sizes of various objects in the protocol.
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Topology {
        /// How many bytes the data has.
        pub data_bytes: usize,
        /// How many columns the data has.
        pub data_cols: usize,
        /// How many rows the data has.
        pub data_rows: usize,
        /// How many rows the encoded data has.
        pub encoded_rows: usize,
        /// How many samples each shard has.
        pub samples: usize,
        /// How many column samples we need.
        pub column_samples: usize,
        /// How many shards we need to recover.
        pub min_shards: usize,
        /// How many shards there are in total (each shard containing multiple rows).
        pub total_shards: usize,
    }

    impl Topology {
        const fn with_cols(data_bytes: usize, n: usize, k: usize, cols: usize) -> Self {
            let data_els = F::bits_to_elements(8 * data_bytes);
            let data_rows = data_els.div_ceil(cols);
            let samples = data_rows.div_ceil(n);
            Self {
                data_bytes,
                data_cols: cols,
                data_rows,
                encoded_rows: ((n + k) * samples).next_power_of_two(),
                samples,
                column_samples: 0,
                min_shards: n,
                total_shards: n + k,
            }
        }

        pub(crate) fn required_samples(&self) -> usize {
            let k = BigRational::from_usize(self.encoded_rows - self.data_rows);
            let m = BigRational::from_usize(self.encoded_rows);
            let fraction = (&k + BigRational::from_u64(1)) / (BigRational::from_usize(2) * &m);

            // Compute log2(one_minus). When m is close to n, one_minus is close to 1, making log2(one_minus)
            // a small negative value that requires sufficient precision to correctly capture the sign.
            let one_minus = BigRational::from_usize(1) - &fraction;
            let log_term = one_minus.log2_ceil(LOG2_PRECISION);
            if log_term >= BigRational::from_u64(0) {
                return usize::MAX;
            }

            let required = BigRational::from_usize(SECURITY_BITS) / -log_term;
            required.ceil_to_u128().unwrap_or(u128::MAX) as usize
        }

        fn correct_column_samples(&mut self) {
            // We make sure we have enough column samples to get 126 bits of security.
            //
            // This effectively does two elements per column. To get strictly greater
            // than 128 bits, we would need to add another column per column_sample.
            // We also have less than 128 bits in other places because of the bounds
            // on the messages encoded size.
            self.column_samples =
                F::bits_to_elements(SECURITY_BITS) * self.required_samples().div_ceil(self.samples);
        }

        /// Figure out what size different values will have, based on the config and the data.
        pub fn reckon(config: &Config, data_bytes: usize) -> Self {
            let n = config.minimum_shards as usize;
            let k = config.extra_shards as usize;
            // The following calculations don't tolerate data_bytes = 0, so we
            // temporarily correct that to be at least 1, then make sure to adjust
            // it back again to 0.
            let corrected_data_bytes = data_bytes.max(1);
            // The goal here is to try and maximize the number of columns in the
            // data. ZODA is more efficient the more columns there are. However,
            // we need to make sure that every shard has enough samples to guarantee
            // correct encoding, and that the number of encoded rows can contain
            // all of the samples in each shard, without overlap.
            //
            // To determine if a column configuration is good, we need to choose
            // the number of encoded rows. To do this, we pick a number of samples
            // `S` such that `S * n >= data_rows`. Then, our encoded rows will
            // equal `((n + k) * S).next_power_of_two()`. If the number of required
            // samples `R` for this configuration satisfies `(n + k) * R <= encoded_rows`,
            // then this configuration is valid, using `R` as the necessary number
            // of samples.
            //
            // We try increasing column counts, picking the configuration that's good.
            // It's possible that the first configuration, with one column, is not good.
            // To correct for that, we need to add extra checksum columns to guarantee
            // security.
            let mut out = Self::with_cols(corrected_data_bytes, n, k, 1);
            loop {
                let attempt = Self::with_cols(corrected_data_bytes, n, k, out.data_cols + 1);
                let required_samples = attempt.required_samples();
                if required_samples.saturating_mul(n + k) <= attempt.encoded_rows {
                    out = Self {
                        samples: required_samples.max(attempt.samples),
                        ..attempt
                    };
                } else {
                    break;
                }
            }
            out.correct_column_samples();
            out.data_bytes = data_bytes;
            out
        }

        pub fn check_index(&self, i: u16) -> Result<(), Error> {
            if (0..self.total_shards).contains(&(i as usize)) {
                return Ok(());
            }
            Err(Error::InvalidIndex(i))
        }
    }
}
use topology::Topology;

/// A shard of data produced by the encoding scheme.
#[derive(Clone)]
pub struct Shard<H: Hasher> {
    data_bytes: usize,
    root: H::Digest,
    inclusion_proof: Proof<H::Digest>,
    rows: Matrix,
    checksum: Arc<Matrix>,
}

impl<H: Hasher> PartialEq for Shard<H> {
    fn eq(&self, other: &Self) -> bool {
        self.data_bytes == other.data_bytes
            && self.root == other.root
            && self.inclusion_proof == other.inclusion_proof
            && self.rows == other.rows
            && self.checksum == other.checksum
    }
}

impl<H: Hasher> Eq for Shard<H> {}

impl<H: Hasher> EncodeSize for Shard<H> {
    fn encode_size(&self) -> usize {
        self.data_bytes.encode_size()
            + self.root.encode_size()
            + self.inclusion_proof.encode_size()
            + self.rows.encode_size()
            + self.checksum.encode_size()
    }
}

impl<H: Hasher> Write for Shard<H> {
    fn write(&self, buf: &mut impl BufMut) {
        self.data_bytes.write(buf);
        self.root.write(buf);
        self.inclusion_proof.write(buf);
        self.rows.write(buf);
        self.checksum.write(buf);
    }
}

impl<H: Hasher> Read for Shard<H> {
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
            rows: Read::read_cfg(buf, &max_els)?,
            checksum: Arc::new(Read::read_cfg(buf, &max_els)?),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<H: Hasher> arbitrary::Arbitrary<'_> for Shard<H>
where
    H::Digest: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            data_bytes: u.arbitrary::<u32>()? as usize,
            root: u.arbitrary()?,
            inclusion_proof: u.arbitrary()?,
            rows: u.arbitrary()?,
            checksum: Arc::new(u.arbitrary()?),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ReShard<H: Hasher> {
    inclusion_proof: Proof<H::Digest>,
    shard: Matrix,
}

impl<H: Hasher> PartialEq for ReShard<H> {
    fn eq(&self, other: &Self) -> bool {
        self.inclusion_proof == other.inclusion_proof && self.shard == other.shard
    }
}

impl<H: Hasher> Eq for ReShard<H> {}

impl<H: Hasher> EncodeSize for ReShard<H> {
    fn encode_size(&self) -> usize {
        self.inclusion_proof.encode_size() + self.shard.encode_size()
    }
}

impl<H: Hasher> Write for ReShard<H> {
    fn write(&self, buf: &mut impl BufMut) {
        self.inclusion_proof.write(buf);
        self.shard.write(buf);
    }
}

impl<H: Hasher> Read for ReShard<H> {
    type Cfg = crate::CodecConfig;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let max_data_bits = cfg.maximum_shard_size.saturating_mul(8);
        let max_data_els = F::bits_to_elements(max_data_bits).max(1);
        Ok(Self {
            // Worst case: every row is one data element, and the sample size is all rows.
            // TODO (#2506): use correct bounds on inclusion proof size
            inclusion_proof: Read::read_cfg(buf, &max_data_els)?,
            shard: Read::read_cfg(buf, &max_data_els)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<H: Hasher> arbitrary::Arbitrary<'_> for ReShard<H>
where
    H::Digest: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            inclusion_proof: u.arbitrary()?,
            shard: u.arbitrary()?,
        })
    }
}

/// A ZODA shard that has been checked for integrity already.
pub struct CheckedShard {
    index: usize,
    shard: Matrix,
}

/// Take indices up to `total`, and shuffle them.
///
/// The shuffle depends, deterministically, on the transcript.
fn shuffle_indices(transcript: &Transcript, total: usize) -> Vec<Location> {
    let mut out = (0..total as u64).map(Location::from).collect::<Vec<_>>();
    out.shuffle(&mut transcript.noise(b"shuffle"));
    out
}

/// Create a checking matrix of the right shape.
///
/// This matrix is random, using the transcript as a deterministic source of randomness.
fn checking_matrix(transcript: &Transcript, topology: &Topology) -> Matrix {
    Matrix::rand(
        &mut transcript.noise(b"checking matrix"),
        topology.data_cols,
        topology.column_samples,
    )
}

/// Data used to check [ReShard]s.
#[derive(Clone)]
pub struct CheckingData<H: Hasher> {
    topology: Topology,
    root: H::Digest,
    checking_matrix: Matrix,
    encoded_checksum: Matrix,
    shuffled_indices: Vec<Location>,
}

impl<H: Hasher> CheckingData<H> {
    /// Calculate the values of this struct, based on information received.
    ///
    /// We control `config`.
    ///
    /// We're provided with `commitment`, which should hash over `root`,
    /// and `data_bytes`.
    ///
    /// We're also give a `checksum` matrix used to check the shards we receive.
    fn reckon(
        config: &Config,
        commitment: &Summary,
        data_bytes: usize,
        root: H::Digest,
        checksum: &Matrix,
    ) -> Result<Self, Error> {
        let topology = Topology::reckon(config, data_bytes);
        let mut transcript = Transcript::new(NAMESPACE);
        transcript.commit((topology.data_bytes as u64).encode());
        transcript.commit(root.encode());
        let expected_commitment = transcript.summarize();
        if *commitment != expected_commitment {
            return Err(Error::InvalidShard);
        }
        let transcript = Transcript::resume(expected_commitment);
        let checking_matrix = checking_matrix(&transcript, &topology);
        if checksum.rows() != topology.data_rows || checksum.cols() != topology.column_samples {
            return Err(Error::InvalidShard);
        }
        let encoded_checksum = checksum
            .as_polynomials(topology.encoded_rows)
            .expect("checksum has too many rows")
            .evaluate()
            .data();
        let shuffled_indices = shuffle_indices(&transcript, topology.encoded_rows);

        Ok(Self {
            topology,
            root,
            checking_matrix,
            encoded_checksum,
            shuffled_indices,
        })
    }

    fn check(&self, index: u16, reshard: &ReShard<H>) -> Result<CheckedShard, Error> {
        self.topology.check_index(index)?;
        if reshard.shard.rows() != self.topology.samples
            || reshard.shard.cols() != self.topology.data_cols
        {
            return Err(Error::InvalidReShard);
        }
        let index = index as usize;
        let these_shuffled_indices = &self.shuffled_indices
            [index * self.topology.samples..(index + 1) * self.topology.samples];
        let proof_elements = {
            these_shuffled_indices
                .iter()
                .zip(reshard.shard.iter())
                .map(|(&i, row)| (row_digest::<H>(row), i))
                .collect::<Vec<_>>()
        };
        if !reshard.inclusion_proof.verify_multi_inclusion(
            &mut StandardHasher::<H>::new(),
            &proof_elements,
            &self.root,
        ) {
            return Err(Error::InvalidReShard);
        }
        let shard_checksum = reshard.shard.mul(&self.checking_matrix);
        // Check that the shard checksum rows match the encoded checksums
        for (row, &i) in shard_checksum.iter().zip(these_shuffled_indices) {
            if row != &self.encoded_checksum[u64::from(i) as usize] {
                return Err(Error::InvalidReShard);
            }
        }
        Ok(CheckedShard {
            index,
            shard: reshard.shard.clone(),
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid shard")]
    InvalidShard,
    #[error("invalid reshard")]
    InvalidReShard,
    #[error("invalid index {0}")]
    InvalidIndex(u16),
    #[error("insufficient shards {0} < {1}")]
    InsufficientShards(usize, usize),
    #[error("insufficient unique rows {0} < {1}")]
    InsufficientUniqueRows(usize, usize),
    #[error("failed to create inclusion proof: {0}")]
    FailedToCreateInclusionProof(MmrError),
}

// TODO (#2506): rename this to `_COMMONWARE_CODING_ZODA`
const NAMESPACE: &[u8] = b"commonware-zoda";

#[derive(Clone, Copy)]
pub struct Zoda<H> {
    _marker: PhantomData<H>,
}

impl<H> std::fmt::Debug for Zoda<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Zoda")
    }
}

impl<H: Hasher> Scheme for Zoda<H> {
    type Commitment = Summary;

    type Shard = Shard<H>;

    type ReShard = ReShard<H>;

    type CheckingData = CheckingData<H>;

    type CheckedShard = CheckedShard;

    type Error = Error;

    fn encode(
        config: &Config,
        data: impl bytes::Buf,
        concurrency: usize,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        // Step 1: arrange the data as a matrix.
        let data_bytes = data.remaining();
        let topology = Topology::reckon(config, data_bytes);
        let data = Matrix::init(
            topology.data_rows,
            topology.data_cols,
            F::stream_from_u64s(iter_u64_le(data)),
        );

        // Step 2: Encode the data.
        let encoded_data = data
            .as_polynomials(topology.encoded_rows)
            .expect("data has too many rows")
            .evaluate()
            .data();

        // Step 3: Commit to the rows of the data.
        let mut hasher = StandardHasher::<H>::new();
        let mut mmr = DirtyMmr::new();
        if concurrency > 1 {
            let pool = ThreadPoolBuilder::new()
                .num_threads(concurrency)
                .build()
                .expect("failed to build thread pool");
            let row_hashes = pool.install(|| {
                (0..encoded_data.rows())
                    .into_par_iter()
                    .map(|i| row_digest::<H>(&encoded_data[i]))
                    .collect::<Vec<_>>()
            });
            for hash in &row_hashes {
                mmr.add(&mut hasher, hash);
            }
        } else {
            for row in encoded_data.iter() {
                mmr.add(&mut hasher, &row_digest::<H>(row));
            }
        }
        let mmr = mmr.merkleize(&mut hasher, None);
        let root = *mmr.root();

        // Step 4: Commit to the root, and the size of the data.
        let mut transcript = Transcript::new(NAMESPACE);
        transcript.commit((topology.data_bytes as u64).encode());
        transcript.commit(root.encode());
        let commitment = transcript.summarize();

        // Step 5: Generate a checking matrix, and a shuffling with the commitment.
        let transcript = Transcript::resume(commitment);
        let checking_matrix = checking_matrix(&transcript, &topology);
        let shuffled_indices = shuffle_indices(&transcript, encoded_data.rows());

        // Step 6: Multiply the data with the checking matrix.
        let checksum = Arc::new(data.mul(&checking_matrix));

        // Step 7: Produce the shards.
        // We can't use "chunks" because we need to handle a sample size of 0
        let index_chunks = (0..topology.total_shards)
            .map(|i| &shuffled_indices[i * topology.samples..(i + 1) * topology.samples]);
        let shards = index_chunks
            .map(|indices| {
                let rows = Matrix::init(
                    indices.len(),
                    topology.data_cols,
                    indices
                        .iter()
                        .flat_map(|&i| encoded_data[u64::from(i) as usize].iter().copied()),
                );
                let inclusion_proof = block_on(multi_proof(&mmr, indices))
                    .map_err(Error::FailedToCreateInclusionProof)?;
                Ok(Shard {
                    data_bytes,
                    root,
                    inclusion_proof,
                    rows,
                    checksum: checksum.clone(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok((commitment, shards))
    }

    fn reshard(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: Self::Shard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::ReShard), Self::Error> {
        let reshard = ReShard {
            inclusion_proof: shard.inclusion_proof,
            shard: shard.rows,
        };
        let checking_data = CheckingData::reckon(
            config,
            commitment,
            shard.data_bytes,
            shard.root,
            shard.checksum.as_ref(),
        )?;
        let checked_shard = checking_data.check(index, &reshard)?;
        Ok((checking_data, checked_shard, reshard))
    }

    fn check(
        _config: &Config,
        _commitment: &Self::Commitment,
        checking_data: &Self::CheckingData,
        index: u16,
        reshard: Self::ReShard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        checking_data.check(index, &reshard)
    }

    fn decode(
        _config: &Config,
        _commitment: &Self::Commitment,
        checking_data: Self::CheckingData,
        shards: &[Self::CheckedShard],
        _concurrency: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let Topology {
            encoded_rows,
            data_cols,
            samples,
            data_rows,
            data_bytes,
            min_shards,
            ..
        } = checking_data.topology;
        if shards.len() < min_shards {
            return Err(Error::InsufficientShards(shards.len(), min_shards));
        }
        let mut evaluation = EvaluationVector::empty(encoded_rows.ilog2() as usize, data_cols);
        for shard in shards {
            let indices =
                &checking_data.shuffled_indices[shard.index * samples..(shard.index + 1) * samples];
            for (&i, row) in indices.iter().zip(shard.shard.iter()) {
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
}

impl<H: Hasher> ValidatingScheme for Zoda<H> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CodecConfig, Config};
    use commonware_cryptography::Sha256;

    const CONCURRENCY: usize = 1;

    #[test]
    fn topology_reckon_handles_small_extra_shards() {
        let config = Config {
            minimum_shards: 3,
            extra_shards: 1,
        };
        let topology = Topology::reckon(&config, 16);
        assert_eq!(topology.min_shards, 3);
        assert_eq!(topology.total_shards, 4);

        // Verify we hit the 1-column fallback and the security invariant holds.
        // When the loop in reckon() exits without finding a multi-column config,
        // correct_column_samples() must compensate by adding column samples.
        assert_eq!(topology.data_cols, 1);
        let required = topology.required_samples();
        let provided = topology.samples * (topology.column_samples / 2);
        assert!(
            provided >= required,
            "security invariant violated: provided {provided} < required {required}"
        );
    }

    #[test]
    fn reshard_roundtrip_handles_field_packing() {
        use bytes::BytesMut;
        use commonware_cryptography::Sha256;

        let config = Config {
            minimum_shards: 3,
            extra_shards: 2,
        };
        let data = vec![0xAA; 64];

        let (commitment, shards) =
            Zoda::<Sha256>::encode(&config, data.as_slice(), CONCURRENCY).unwrap();
        let shard = shards.into_iter().next().unwrap();

        let (_, _, reshard) = Zoda::<Sha256>::reshard(&config, &commitment, 0, shard).unwrap();

        let mut buf = BytesMut::new();
        reshard.write(&mut buf);
        let mut bytes = buf.freeze();
        let decoded = ReShard::<Sha256>::read_cfg(
            &mut bytes,
            &CodecConfig {
                maximum_shard_size: data.len(),
            },
        )
        .unwrap();

        assert_eq!(decoded, reshard);
    }

    #[test]
    fn decode_rejects_duplicate_indices() {
        let config = Config {
            minimum_shards: 2,
            extra_shards: 0,
        };
        let data = b"duplicate shard coverage";
        let (commitment, shards) = Zoda::<Sha256>::encode(&config, &data[..], CONCURRENCY).unwrap();
        let shard0 = shards[0].clone();
        let (checking_data, checked_shard0, _reshard0) =
            Zoda::<Sha256>::reshard(&config, &commitment, 0, shard0).unwrap();
        let duplicate = CheckedShard {
            index: checked_shard0.index,
            shard: checked_shard0.shard.clone(),
        };
        let shards = vec![checked_shard0, duplicate];
        let result =
            Zoda::<Sha256>::decode(&config, &commitment, checking_data, &shards, CONCURRENCY);
        match result {
            Err(Error::InsufficientUniqueRows(actual, expected)) => {
                assert!(actual < expected);
            }
            other => panic!("expected insufficient unique rows error, got {other:?}"),
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Shard<Sha256>>,
            CodecConformance<ReShard<Sha256>>,
        }
    }
}
