use crate::{
    field::F,
    poly::{EvaluationVector, Matrix},
    Config, Scheme,
};
use bytes::BufMut;
use commonware_codec::{Encode, EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    transcript::{Summary, Transcript},
    Hasher,
};
use commonware_storage::bmt::{Builder, Proof};
use rand::seq::SliceRandom as _;
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

fn required_samples(min_rows: usize, encoded_rows: usize) -> usize {
    let n = min_rows as f64;
    let k = (encoded_rows - min_rows) as f64;
    let required = 128.0 / -(1.0 - (k + 1.0) / (2.0 * (n + k))).log2();
    required.ceil() as usize
}

/// Takes the limit of [required_samples] as the number of samples per row goes to infinity.
///
/// The actual number of required samples for a given n * samples and k * samples
/// will be less.
fn required_samples_upper_bound(n: usize, k: usize) -> usize {
    (128.0 / -(1.0 - k as f64 / (2.0 * (n + k) as f64)).log2()).ceil() as usize
}

fn enough_samples(n: usize, k: usize, samples: usize) -> bool {
    let min_rows = n * samples;
    let encoded_rows = ((n + k) * samples).next_power_of_two();
    let required = required_samples(min_rows, encoded_rows);
    samples >= required
}

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
        let column_samples =
            F::bits_to_elements(126) * required_samples(data_rows, encoded_rows).div_ceil(samples);
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

    fn check_index(&self, i: u16) -> Result<(), ZodaError> {
        if (0..self.total_shards).contains(&(i as usize)) {
            return Ok(());
        }
        Err(ZodaError::InvalidIndex(i))
    }
}

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
            rows: Read::read_cfg(buf, &(topology.data_cols * topology.data_rows))?,
            checksum: Arc::new(Read::read_cfg(
                buf,
                &(topology.data_cols * topology.data_rows),
            )?),
        })
    }
}

#[derive(Clone)]
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
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &max_data_bytes: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let max_data_els = max_data_bytes.div_ceil(F::SIZE);
        Ok(Self {
            // Worst case: every row is one data element, and the sample size is all rows.
            inclusion_proofs: Read::read_cfg(buf, &(RangeCfg::from(..=max_data_els), ()))?,
            shard: Read::read_cfg(buf, &max_data_els)?,
        })
    }
}

pub struct CheckedShard {
    index: usize,
    shard: Matrix,
}

fn shuffle_indices(transcript: &Transcript, total: usize) -> Vec<usize> {
    let mut out = (0..total).collect::<Vec<_>>();
    out.shuffle(&mut transcript.noise(b"shuffle"));
    out
}

fn checking_matrix(transcript: &Transcript, topology: &Topology) -> Matrix {
    Matrix::rand(
        &mut transcript.noise(b"checking matrix"),
        topology.data_cols,
        topology.column_samples,
    )
}

#[derive(Clone)]
pub struct CheckingData<H: Hasher> {
    topology: Topology,
    root: H::Digest,
    checking_matrix: Matrix,
    encoded_checksum: Matrix,
    shuffled_indices: Vec<usize>,
}

impl<H: Hasher> CheckingData<H> {
    fn reckon(
        config: &Config,
        commitment: &Summary,
        data_bytes: usize,
        root: H::Digest,
        checksum: &Matrix,
    ) -> Result<Self, ZodaError> {
        let topology = Topology::reckon(config, data_bytes);
        let mut transcript = Transcript::new(NAMESPACE);
        transcript.commit((topology.data_bytes as u64).encode());
        transcript.commit(root.encode());
        let expected_commitment = transcript.summarize();
        if *commitment != expected_commitment {
            return Err(ZodaError::InvalidShard);
        }
        let transcript = Transcript::resume(expected_commitment);
        let checking_matrix = checking_matrix(&transcript, &topology);
        if checksum.rows() != topology.data_rows || checksum.cols() != topology.column_samples {
            return Err(ZodaError::InvalidShard);
        }
        let encoded_checksum = checksum
            .as_polynomials(topology.encoded_rows)
            .evaluate()
            .data();
        let shuffled_indices = shuffle_indices(&transcript, topology.encoded_rows);

        Ok(Self {
            topology,
            root: root,
            checking_matrix,
            encoded_checksum,
            shuffled_indices,
        })
    }

    fn check(&self, index: u16, reshard: &ReShard<H>) -> Result<CheckedShard, ZodaError> {
        self.topology.check_index(index)?;
        if reshard.shard.rows() != self.topology.samples
            || reshard.shard.cols() != self.topology.data_cols
            || reshard.inclusion_proofs.len() != reshard.shard.rows()
        {
            return Err(ZodaError::InvalidReShard);
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
                .map_err(|_| ZodaError::InvalidReShard)?;
        }
        let shard_checksum = reshard.shard.mul(&self.checking_matrix);
        // Check that the shard checksum rows match the encoded checksums
        for (row, &i) in shard_checksum.iter().zip(these_shuffled_indices) {
            if row != &self.encoded_checksum[i] {
                return Err(ZodaError::InvalidReShard);
            }
        }
        Ok(CheckedShard {
            index,
            shard: reshard.shard.clone(),
        })
    }
}

#[derive(Debug, Error)]
pub enum ZodaError {
    #[error("invalid shard")]
    InvalidShard,
    #[error("invalid reshard")]
    InvalidReShard,
    #[error("invalid index {0}")]
    InvalidIndex(u16),
    #[error("insufficient shards {0} < {1}")]
    InsufficientShards(usize, usize),
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

    type Error = ZodaError;

    fn encode(
        config: &Config,
        data: impl bytes::Buf,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        let data_bytes = data.remaining();
        let topology = Topology::reckon(config, data_bytes);
        let data = Matrix::init(
            topology.data_rows,
            topology.data_cols,
            F::stream_from_u64s(iter_u64_le(data)),
        );
        let encoded_data = data.as_polynomials(topology.encoded_rows).evaluate().data();
        let mut builder = Builder::<H>::new(encoded_data.rows());
        for row in encoded_data.iter() {
            builder.add(&F::slice_digest::<H>(row));
        }
        let tree = builder.build();
        let root = tree.root();
        let mut transcript = Transcript::new(NAMESPACE);
        transcript.commit((topology.data_bytes as u64).encode());
        transcript.commit(root.encode());
        let commitment = transcript.summarize();
        let transcript = Transcript::resume(commitment);

        let checking_matrix = checking_matrix(&transcript, &topology);
        let checksum = Arc::new(data.mul(&checking_matrix));

        let shuffled_indices = shuffle_indices(&transcript, encoded_data.rows());
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
            return Err(ZodaError::InsufficientShards(shards.len(), min_shards));
        }
        let mut evaluation = EvaluationVector::empty(encoded_rows.ilog2() as usize, data_cols);
        for shard in shards {
            let indices =
                &checking_data.shuffled_indices[shard.index * samples..(shard.index + 1) * samples];
            for (&i, row) in indices.iter().zip(shard.shard.iter()) {
                evaluation.fill_row(i, row);
            }
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
