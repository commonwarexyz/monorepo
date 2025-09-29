use crate::{Config, Scheme};
use bytes::BufMut;
use commonware_codec::{Encode, EncodeSize, Read, Write};
use commonware_cryptography::{
    transcript::{Summary, Transcript},
    Hasher,
};
use commonware_storage::bmt::{self, Builder};
use rand::seq::SliceRandom;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::{marker::PhantomData, sync::Arc};
use thiserror::Error;

const NAMESPACE: &[u8] = b"commonware-zoda";

fn required_samples(config: &Config) -> usize {
    let k = config.extra_shards as f64;
    let n = config.minimum_shards as f64;
    let required = 128.0 / -(1.0 - (k + 1.0) / (n + k)).log2();
    required.ceil() as usize
}

#[derive(Clone, Debug)]
struct Topology {
    n: usize,
    k: usize,
    data_bytes: usize,
    row_samples: usize,
    check_columns: usize,
}

impl Topology {
    fn reckon(config: &Config, data_bytes: usize) -> Self {
        let n = config.minimum_shards as usize;
        let k = config.extra_shards as usize;
        let samples = required_samples(config);
        // How large is the data in field elements?
        let data_fe = data_bytes.div_ceil(2);
        // We want to get as many row samples as we can, but we don't want to
        // pad the data. So, our approach is to set the row samples as high as
        // we can, and then decrease it until the data fits, and we're not
        // over the limits of what the RS encoder can support.
        //
        // INVARIANT: row_samples * check_columns >= samples.
        let mut row_samples = samples;
        let mut check_columns = 1;
        while {
            let original_count = row_samples * n;
            let recovery_count = row_samples * k;
            row_samples > 1
                && (original_count > data_fe
                    || !ReedSolomonEncoder::supports(original_count, recovery_count))
        } {
            check_columns += 1;
            row_samples = samples.div_ceil(check_columns);
        }
        Self {
            n,
            k,
            data_bytes,
            row_samples,
            check_columns,
        }
    }

    fn min_rows(&self) -> usize {
        self.row_samples * self.n
    }

    fn extra_rows(&self) -> usize {
        self.row_samples * self.k
    }

    fn total_rows(&self) -> usize {
        self.min_rows() + self.extra_rows()
    }

    fn chunk_size(&self) -> usize {
        let out = self.data_bytes.div_ceil(self.min_rows());
        // Make sure the chunk size is even, rounding up, and making sure it's
        // at least 2.
        (out + (out & 1)).max(2)
    }
}

#[derive(Clone)]
struct Row<H: Hasher> {
    data: Vec<u8>,
    inclusion_proof: bmt::Proof<H>,
}

impl<H: Hasher> PartialEq for Row<H> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.inclusion_proof == other.inclusion_proof
    }
}
impl<H: Hasher> Eq for Row<H> {}

impl<H: Hasher> EncodeSize for Row<H> {
    fn encode_size(&self) -> usize {
        todo!()
    }
}

impl<H: Hasher> Write for Row<H> {
    fn write(&self, buf: &mut impl BufMut) {
        todo!()
    }
}

impl<H: Hasher> Read for Row<H> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        todo!()
    }
}

#[derive(Clone)]
pub struct Shard<H: Hasher> {
    rows: Vec<Row<H>>,
    data_bytes: u64,
    root: H::Digest,
}

impl<H: Hasher> PartialEq for Shard<H> {
    fn eq(&self, other: &Self) -> bool {
        self.rows == other.rows && self.data_bytes == other.data_bytes && self.root == other.root
    }
}

impl<H: Hasher> Eq for Shard<H> {}

impl<H: Hasher> EncodeSize for Shard<H> {
    fn encode_size(&self) -> usize {
        todo!()
    }
}

impl<H: Hasher> Write for Shard<H> {
    fn write(&self, buf: &mut impl BufMut) {
        todo!()
    }
}

impl<H: Hasher> Read for Shard<H> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        todo!()
    }
}

#[derive(Clone)]
pub struct ReShard<H: Hasher> {
    rows: Arc<Vec<Row<H>>>,
}

impl<H: Hasher> PartialEq for ReShard<H> {
    fn eq(&self, other: &Self) -> bool {
        self.rows == other.rows
    }
}

impl<H: Hasher> Eq for ReShard<H> {}

impl<H: Hasher> EncodeSize for ReShard<H> {
    fn encode_size(&self) -> usize {
        todo!()
    }
}

impl<H: Hasher> Write for ReShard<H> {
    fn write(&self, buf: &mut impl BufMut) {
        todo!()
    }
}

impl<H: Hasher> Read for ReShard<H> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        todo!()
    }
}

pub struct CheckedShard<H: Hasher> {
    reshard: ReShard<H>,
    indices: Vec<u16>,
}

fn shuffle_indices(transcript: &Transcript, total: u16) -> Vec<u16> {
    let mut out = (0..total).collect::<Vec<_>>();
    out.shuffle(&mut transcript.noise(b"shuffle"));
    out
}

#[derive(Clone)]
pub struct CheckingData<H: Hasher> {
    root: H::Digest,
    topology: Topology,
    shuffled_indices: Vec<u16>,
}

impl<H: Hasher> CheckingData<H> {
    fn reckon(
        config: &Config,
        commitment: &Summary,
        root: H::Digest,
        data_bytes: u64,
    ) -> Result<Self, ZodaError> {
        let topology = Topology::reckon(config, data_bytes as usize);
        let expected_commitment = Transcript::new(NAMESPACE)
            .commit(data_bytes.encode())
            .commit(root.encode())
            .summarize();
        if expected_commitment != *commitment {
            return Err(ZodaError::Something);
        }
        let transcript = Transcript::resume(expected_commitment);
        let shuffled_indices = shuffle_indices(&transcript, topology.total_rows() as u16);
        Ok(Self {
            root,
            topology,
            shuffled_indices,
        })
    }

    fn check(&self, index: u16, reshard: &ReShard<H>) -> Result<CheckedShard<H>, ZodaError> {
        if (index as usize) >= self.topology.n + self.topology.k {
            return Err(ZodaError::Something);
        }
        if reshard.rows.len() != self.topology.row_samples {
            return Err(ZodaError::Something);
        }
        let start = index as usize * self.topology.row_samples;
        let mut indices = Vec::with_capacity(reshard.rows.len());
        for (i, row) in reshard.rows.iter().enumerate() {
            if row.data.len() != self.topology.chunk_size() {
                return Err(ZodaError::Something);
            }
            let position = self.shuffled_indices[start + i];
            indices.push(position);
            row.inclusion_proof
                .verify(
                    &mut H::new(),
                    &H::new().update(&row.data).finalize(),
                    position as u32,
                    &self.root,
                )
                .map_err(|_| ZodaError::Something)?;
        }

        Ok(CheckedShard {
            reshard: reshard.clone(),
            indices,
        })
    }
}

#[derive(Debug, Error)]
pub enum ZodaError {
    #[error("something")]
    Something,
}

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

    type CheckedShard = CheckedShard<H>;

    type Error = ZodaError;

    fn encode(
        config: &Config,
        mut data: impl bytes::Buf,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        let topology = Topology::reckon(config, data.remaining());

        // Now, we're going to construct an encoder.
        let (tree, mut row_data) = {
            let mut row_data: Vec<Vec<u8>> = Vec::with_capacity(topology.total_rows());
            let mut builder = Builder::<H>::new(topology.total_rows());
            let mut encoder = ReedSolomonEncoder::new(
                topology.min_rows(),
                topology.extra_rows(),
                topology.chunk_size(),
            )
            .expect("TODO");
            for _ in 0..topology.min_rows() {
                let mut chunk = vec![0u8; topology.chunk_size()];
                let to_copy = chunk.len().min(data.remaining());
                data.copy_to_slice(&mut chunk[..to_copy]);
                encoder.add_original_shard(&chunk).expect("TODO");
                builder.add(&H::new().update(&chunk).finalize());
                row_data.push(chunk);
            }
            let encoding_result = encoder.encode().expect("TODO");
            for chunk in encoding_result.recovery_iter() {
                builder.add(&H::new().update(chunk).finalize());
                row_data.push(chunk.to_vec());
            }
            (builder.build(), row_data)
        };
        let root = tree.root();
        let mut transcript = Transcript::new(NAMESPACE);
        transcript.commit((topology.data_bytes as u64).encode());
        transcript.commit(root.encode());
        let commitment = transcript.summarize();
        let transcript = Transcript::resume(commitment);

        let shuffled_indices = shuffle_indices(&transcript, topology.total_rows() as u16);
        let shards: Vec<Self::Shard> = (0..config.minimum_shards + config.extra_shards)
            .map(|index| {
                let rows = (0..topology.row_samples)
                    .map(|i| {
                        let local_index =
                            shuffled_indices[topology.row_samples * index as usize + i];
                        Row {
                            data: std::mem::take(&mut row_data[local_index as usize]),
                            inclusion_proof: tree.proof(local_index.into()).expect("TODO"),
                        }
                    })
                    .collect();
                Shard {
                    rows,
                    data_bytes: topology.data_bytes as u64,
                    root,
                }
            })
            .collect();

        Ok((commitment, shards))
    }

    fn reshard(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: Self::Shard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::ReShard), Self::Error> {
        let checking_data = CheckingData::reckon(config, commitment, shard.root, shard.data_bytes)?;
        let reshard = ReShard {
            rows: Arc::new(shard.rows),
        };
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
        let topology = &checking_data.topology;
        if shards.len() < topology.n {
            return Err(ZodaError::Something);
        }
        let mut decoder = ReedSolomonDecoder::new(
            topology.min_rows(),
            topology.extra_rows(),
            topology.chunk_size(),
        )
        .map_err(|_| ZodaError::Something)?;
        let chunk_size = topology.chunk_size();
        let mut out = vec![0u8; chunk_size * topology.min_rows()];
        for shard in shards {
            for (index, row) in shard.indices.iter().zip(shard.reshard.rows.iter()) {
                let data = row.data.as_slice();
                let index = *index as usize;
                if index < topology.min_rows() {
                    out[chunk_size * index..chunk_size * (index + 1)].copy_from_slice(data);
                    decoder
                        .add_original_shard(index, data)
                        .map_err(|_| ZodaError::Something)?;
                } else {
                    decoder
                        .add_recovery_shard(index - topology.min_rows(), data)
                        .map_err(|_| ZodaError::Something)?;
                }
            }
        }
        let res = decoder.decode().map_err(|_| ZodaError::Something)?;
        for (i, chunk) in res.restored_original_iter() {
            out[chunk_size * i..chunk_size * (i + 1)].copy_from_slice(chunk);
        }
        out.truncate(topology.data_bytes);
        Ok(out)
    }
}
