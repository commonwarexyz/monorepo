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
//!    - rows i..(i + 1) * S of Y, along with a proof of inclusion in V, at the original index.
//!
//! ## Re-Sharding
//!
//! When re-transmitting a shard to other people, only the following are transmitted:
//! - rows i..(i + 1) * S of Y, along with the inclusion proofs.
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
use crate::{
    field::F,
    poly::{EvaluationVector, Matrix},
    Config, Scheme, ValidatingScheme,
};
use bytes::BufMut;
use commonware_codec::{Encode, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    transcript::{Summary, Transcript},
    Hasher,
};
use commonware_storage::bmt::{Builder, Proof};
use commonware_utils::rational::BigRationalExt;
use num_rational::BigRational;
use rand::seq::SliceRandom as _;
use std::{marker::PhantomData, sync::Arc};
use thiserror::Error;

const SECURITY_BITS: usize = 126;
const LOG2_INITIAL_PRECISION: usize = 7;
const LOG2_MAX_PRECISION: usize = 128;

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

fn required_samples_impl(n: usize, m: usize, upper_bound: bool) -> usize {
    assert!(m >= n);
    let k = BigRational::from_usize(m - n);
    let m = BigRational::from_usize(m);
    let skew = BigRational::from_u64(if upper_bound { 0u64 } else { 1u64 });
    let fraction = (&k + &skew) / (BigRational::from_usize(2) * &m);
    if fraction == BigRational::from_u64(0) {
        return usize::MAX;
    }
    let one_minus = BigRational::from_usize(1) - fraction;
    let zero = BigRational::from_u64(0);
    // We need to compute log2(one_minus), which must be negative for the formula below to work.
    // However, when m is very close to n (e.g., n = m = 512), we have:
    //   fraction = (k + skew) / (2m) = 1/(2m) when k=0 and skew=1
    //   one_minus = 1 - 1/(2m) = (2m-1)/(2m)
    //   log2(one_minus) ≈ log2(1 - 1/(2m)) ≈ -1/(2m ln(2)) (very small negative number)
    //
    // With low precision (e.g., 7 bits), log2_ceil rounds up this tiny negative value to 0 or
    // even positive, which would cause us to incorrectly return usize::MAX. For example, with
    // n=m=512, precision 7 gives log2_ceil(1023/1024) = 0, but the true value is ≈ -0.00142.
    //
    // By progressively increasing precision until we get a negative result, we ensure we have
    // enough precision to correctly capture the sign.
    let mut precision = LOG2_INITIAL_PRECISION;
    let mut log_term = one_minus.log2_ceil(precision);
    while log_term >= zero && precision < LOG2_MAX_PRECISION {
        precision += 1;
        log_term = one_minus.log2_ceil(precision);
    }
    if log_term >= zero {
        return usize::MAX;
    }
    let required = BigRational::from_usize(SECURITY_BITS) / -log_term;
    required.ceil_to_u128().unwrap_or(u128::MAX) as usize
}

fn required_samples(min_rows: usize, encoded_rows: usize) -> usize {
    required_samples_impl(min_rows, encoded_rows, false)
}

/// Takes the limit of [required_samples] as the number of samples per row goes to infinity.
///
/// The actual number of required samples for a given n * samples and m * samples
/// will be less.
fn required_samples_upper_bound(n: usize, m: usize) -> usize {
    required_samples_impl(n, m, true)
}

fn enough_samples(n: usize, k: usize, samples: usize) -> bool {
    let min_rows = n * samples;
    let encoded_rows = ((n + k) * samples).next_power_of_two();
    let required = required_samples(min_rows, encoded_rows);
    samples >= required
}

/// Contains the sizes of various objects in the protocol.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Topology {
    /// How many bytes the data has.
    data_bytes: usize,
    /// How many columns the data has.
    data_cols: usize,
    /// How many rows the data has.
    data_rows: usize,
    /// How many rows the encoded data has.
    encoded_rows: usize,
    /// How many samples each shard has.
    samples: usize,
    /// How many column samples we need.
    column_samples: usize,
    /// How many shards we need to recover.
    min_shards: usize,
    /// How many shards there are in total (each shard containing multiple rows).
    total_shards: usize,
}

impl Topology {
    /// Figure out what size different values will have, based on the config and the data.
    fn reckon(config: &Config, data_bytes: usize) -> Self {
        let data_bits = 8 * data_bytes;
        let data_els = F::bits_to_elements(data_bits);
        let n = config.minimum_shards as usize;
        let k = config.extra_shards as usize;
        let samples_upper_bound = required_samples_upper_bound(n, n + k);
        let max_samples = (data_els / n).max(1);
        let mut samples = max_samples.min(samples_upper_bound);
        while samples > 1 && enough_samples(n, k, samples - 1) {
            samples -= 1;
        }
        let data_rows = n * samples;
        let data_cols = data_els.div_ceil(data_rows).max(1);
        let encoded_rows = (data_rows + k * samples).next_power_of_two();
        // We make sure we have enough column samples to get 126 bits of security.
        //
        // This effectively does two elements per column. To get strictly greater
        // than 128 bits, we would need to add another column per column_sample.
        // We also have less than 128 bits in other places because of the bounds
        // on the messages encoded size.
        let column_samples = F::bits_to_elements(SECURITY_BITS)
            * required_samples(data_rows, encoded_rows).div_ceil(samples);
        Self {
            data_bytes,
            data_cols,
            data_rows,
            encoded_rows,
            samples,
            column_samples,
            min_shards: n,
            total_shards: n + k,
        }
    }

    fn check_index(&self, i: u16) -> Result<(), Error> {
        if (0..self.total_shards).contains(&(i as usize)) {
            return Ok(());
        }
        Err(Error::InvalidIndex(i))
    }
}

/// A shard of data produced by the encoding scheme.
#[derive(Clone)]
pub struct Shard<H: Hasher> {
    data_bytes: usize,
    root: H::Digest,
    inclusion_proofs: Vec<Proof<H>>,
    rows: Matrix,
    checksum: Arc<Matrix>,
}

impl<H: Hasher> PartialEq for Shard<H> {
    fn eq(&self, other: &Self) -> bool {
        self.data_bytes == other.data_bytes
            && self.root == other.root
            && self.inclusion_proofs == other.inclusion_proofs
            && self.rows == other.rows
            && self.checksum == other.checksum
    }
}

impl<H: Hasher> Eq for Shard<H> {}

impl<H: Hasher> EncodeSize for Shard<H> {
    fn encode_size(&self) -> usize {
        self.data_bytes.encode_size()
            + self.root.encode_size()
            + self.inclusion_proofs.encode_size()
            + self.rows.encode_size()
            + self.checksum.encode_size()
    }
}

impl<H: Hasher> Write for Shard<H> {
    fn write(&self, buf: &mut impl BufMut) {
        self.data_bytes.write(buf);
        self.root.write(buf);
        self.inclusion_proofs.write(buf);
        self.rows.write(buf);
        self.checksum.write(buf);
    }
}

impl<H: Hasher> Read for Shard<H> {
    type Cfg = (usize, Config);

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &(max_data_bytes, ref config): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let data_bytes = usize::read_cfg(buf, &RangeCfg::from(..=max_data_bytes))?;
        let topology = Topology::reckon(config, data_bytes);
        Ok(Self {
            data_bytes,
            root: ReadExt::read(buf)?,
            inclusion_proofs: Read::read_cfg(buf, &(RangeCfg::from(..=topology.samples), ()))?,
            rows: Read::read_cfg(buf, &(topology.data_cols * topology.samples))?,
            checksum: Arc::new(Read::read_cfg(
                buf,
                &(topology.data_rows * topology.column_samples),
            )?),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ReShard<H: Hasher> {
    inclusion_proofs: Vec<Proof<H>>,
    shard: Matrix,
}

impl<H: Hasher> PartialEq for ReShard<H> {
    fn eq(&self, other: &Self) -> bool {
        self.inclusion_proofs == other.inclusion_proofs && self.shard == other.shard
    }
}

impl<H: Hasher> Eq for ReShard<H> {}

impl<H: Hasher> EncodeSize for ReShard<H> {
    fn encode_size(&self) -> usize {
        self.inclusion_proofs.encode_size() + self.shard.encode_size()
    }
}

impl<H: Hasher> Write for ReShard<H> {
    fn write(&self, buf: &mut impl BufMut) {
        self.inclusion_proofs.write(buf);
        self.shard.write(buf);
    }
}

impl<H: Hasher> Read for ReShard<H> {
    type Cfg = crate::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &(max_data_bytes, _): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let max_data_bits = max_data_bytes.saturating_mul(8);
        let max_data_els = F::bits_to_elements(max_data_bits).max(1);
        Ok(Self {
            // Worst case: every row is one data element, and the sample size is all rows.
            inclusion_proofs: Read::read_cfg(buf, &(RangeCfg::from(..=max_data_els), ()))?,
            shard: Read::read_cfg(buf, &max_data_els)?,
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
fn shuffle_indices(transcript: &Transcript, total: usize) -> Vec<usize> {
    let mut out = (0..total).collect::<Vec<_>>();
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
    shuffled_indices: Vec<usize>,
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
            || reshard.inclusion_proofs.len() != reshard.shard.rows()
        {
            return Err(Error::InvalidReShard);
        }
        let index = index as usize;
        let these_shuffled_indices = &self.shuffled_indices
            [index * self.topology.samples..(index + 1) * self.topology.samples];
        // Check every inclusion proof.
        for ((&i, row), proof) in these_shuffled_indices
            .iter()
            .zip(reshard.shard.iter())
            .zip(&reshard.inclusion_proofs)
        {
            proof
                .verify(
                    &mut H::new(),
                    &F::slice_digest::<H>(row),
                    i as u32,
                    &self.root,
                )
                .map_err(|_| Error::InvalidReShard)?;
        }
        let shard_checksum = reshard.shard.mul(&self.checking_matrix);
        // Check that the shard checksum rows match the encoded checksums
        for (row, &i) in shard_checksum.iter().zip(these_shuffled_indices) {
            if row != &self.encoded_checksum[i] {
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
}

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
        let mut builder = Builder::<H>::new(encoded_data.rows());
        for row in encoded_data.iter() {
            builder.add(&F::slice_digest::<H>(row));
        }
        let tree = builder.build();
        let root = tree.root();
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
        let shards = shuffled_indices
            .chunks_exact(topology.samples)
            .take(topology.total_shards)
            .map(|indices| {
                let rows = Matrix::init(
                    indices.len(),
                    topology.data_cols,
                    indices
                        .iter()
                        .flat_map(|&i| encoded_data[i].iter().copied()),
                );
                let inclusion_proofs = indices
                    .iter()
                    .map(|&i| {
                        tree.proof(i as u32)
                            .expect("Impossible: ZODA should always have at least 1 row")
                    })
                    .collect::<Vec<_>>();
                Shard {
                    data_bytes,
                    root,
                    inclusion_proofs,
                    rows,
                    checksum: checksum.clone(),
                }
            })
            .collect::<Vec<_>>();
        Ok((commitment, shards))
    }

    fn reshard(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: Self::Shard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::ReShard), Self::Error> {
        let reshard = ReShard {
            inclusion_proofs: shard.inclusion_proofs,
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
                evaluation.fill_row(i, row);
            }
        }
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
    use crate::Config;
    use commonware_cryptography::Sha256;

    #[test]
    fn required_samples_matches_impl() {
        let min_rows = 3;
        let encoded_rows = 4;
        assert_eq!(
            required_samples(min_rows, encoded_rows),
            required_samples_impl(min_rows, encoded_rows, false)
        );
    }

    #[test]
    fn required_samples_handles_minimal_padding() {
        assert!(required_samples(3, 4) > 0);
    }

    #[test]
    fn required_samples_handles_equal_rows() {
        let value = required_samples_impl(512, 512, false);
        assert!(value > 0);
        assert_ne!(value, usize::MAX);
    }

    #[test]
    fn topology_reckon_handles_small_extra_shards() {
        let config = Config {
            minimum_shards: 3,
            extra_shards: 1,
        };
        let topology = Topology::reckon(&config, 16);
        assert_eq!(topology.min_shards, 3);
        assert_eq!(topology.total_shards, 4);
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

        let (commitment, shards) = Zoda::<Sha256>::encode(&config, data.as_slice()).unwrap();
        let shard = shards.into_iter().next().unwrap();

        let (_, _, reshard) = Zoda::<Sha256>::reshard(&config, &commitment, 0, shard).unwrap();

        let mut buf = BytesMut::new();
        reshard.write(&mut buf);
        let mut bytes = buf.freeze();
        let decoded = ReShard::<Sha256>::read_cfg(&mut bytes, &(data.len(), config)).unwrap();

        assert_eq!(decoded, reshard);
    }

    #[test]
    fn decode_rejects_duplicate_indices() {
        let config = Config {
            minimum_shards: 2,
            extra_shards: 0,
        };
        let data = b"duplicate shard coverage";
        let (commitment, shards) = Zoda::<Sha256>::encode(&config, &data[..]).unwrap();
        let shard0 = shards[0].clone();
        let (checking_data, checked_shard0, _reshard0) =
            Zoda::<Sha256>::reshard(&config, &commitment, 0, shard0).unwrap();
        let duplicate = CheckedShard {
            index: checked_shard0.index,
            shard: checked_shard0.shard.clone(),
        };
        let shards = vec![checked_shard0, duplicate];
        let result = Zoda::<Sha256>::decode(&config, &commitment, checking_data, &shards);
        match result {
            Err(Error::InsufficientUniqueRows(actual, expected)) => {
                assert!(actual < expected);
            }
            other => panic!("expected insufficient unique rows error, got {other:?}"),
        }
    }
}
