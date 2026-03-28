use crate::{
    reed_solomon::{extract_data, prepare_data, CheckedChunk, Chunk, Error as ReedSolomonError},
    Config, Scheme,
};
use bytes::{Buf, Bytes};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_storage::bmt::Builder;
use std::{collections::BTreeSet, marker::PhantomData};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("incompatible shard count for ISA-L gf8 backend: original={original_count}, recovery={recovery_count}")]
    UnsupportedShardCount {
        original_count: usize,
        recovery_count: usize,
    },
    #[error("inconsistent")]
    Inconsistent,
    #[error("invalid proof")]
    InvalidProof,
    #[error("not enough chunks")]
    NotEnoughChunks,
    #[error("duplicate chunk index: {0}")]
    DuplicateIndex(u16),
    #[error("invalid data length: {0}")]
    InvalidDataLength(usize),
    #[error("invalid index: {0}")]
    InvalidIndex(u16),
    #[error("too many total shards: {0}")]
    TooManyTotalShards(u32),
    #[error("checked shard commitment does not match decode commitment")]
    CommitmentMismatch,
}

impl From<ReedSolomonError> for Error {
    fn from(value: ReedSolomonError) -> Self {
        match value {
            ReedSolomonError::Inconsistent => Self::Inconsistent,
            ReedSolomonError::InvalidProof => Self::InvalidProof,
            ReedSolomonError::NotEnoughChunks => Self::NotEnoughChunks,
            ReedSolomonError::DuplicateIndex(index) => Self::DuplicateIndex(index),
            ReedSolomonError::InvalidDataLength(len) => Self::InvalidDataLength(len),
            ReedSolomonError::InvalidIndex(index) => Self::InvalidIndex(index),
            ReedSolomonError::TooManyTotalShards(total) => Self::TooManyTotalShards(total),
            ReedSolomonError::CommitmentMismatch => Self::CommitmentMismatch,
            ReedSolomonError::ReedSolomon(_) => unreachable!("simd backend error should not be converted"),
        }
    }
}

const MAX_ORIGINAL_SHARDS: usize = 127;
const MAX_TOTAL_SHARDS: usize = 255;

fn total_shards(config: &Config) -> Result<u16, Error> {
    let total = config.total_shards();
    total
        .try_into()
        .map_err(|_| Error::TooManyTotalShards(total))
}

fn validate_counts(total: u16, min: u16) -> Result<(usize, usize), Error> {
    assert!(total > min);
    assert!(min > 0);

    let n = total as usize;
    let k = min as usize;
    let m = n - k;
    let supported = k <= MAX_ORIGINAL_SHARDS && n <= MAX_TOTAL_SHARDS;
    if !supported {
        return Err(Error::UnsupportedShardCount {
            original_count: k,
            recovery_count: m,
        });
    }
    Ok((k, m))
}

fn encode_recovery(originals: &[&[u8]], recovery_count: usize) -> Vec<Vec<u8>> {
    let shard_len = originals
        .first()
        .map(|shard| shard.len())
        .expect("at least one original shard");
    let original_count = originals.len();
    let total = original_count + recovery_count;

    let mut encode_matrix = vec![0u8; total * original_count];
    // SAFETY: `encode_matrix` is valid for `total * original_count` bytes.
    unsafe {
        libisal_sys::gf_gen_cauchy1_matrix(
            encode_matrix.as_mut_ptr(),
            total as i32,
            original_count as i32,
        );
    }

    let mut g_tbls = vec![0u8; original_count * recovery_count * 32];
    // SAFETY: buffers are sized per ISA-L requirements and live for the duration
    // of the call. We only pass valid input pointers for shard_len bytes each.
    unsafe {
        libisal_sys::ec_init_tables(
            original_count as i32,
            recovery_count as i32,
            encode_matrix[original_count * original_count..].as_ptr(),
            g_tbls.as_mut_ptr(),
        );
    }

    let data_ptrs: Vec<*const u8> = originals.iter().map(|shard| shard.as_ptr()).collect();
    let mut recovery = vec![vec![0u8; shard_len]; recovery_count];
    let mut recovery_ptrs: Vec<*mut u8> = recovery.iter_mut().map(|shard| shard.as_mut_ptr()).collect();
    // SAFETY: `data_ptrs` and `recovery_ptrs` reference non-overlapping shard
    // buffers of exactly `shard_len` bytes. Tables were initialized for this
    // `(original_count, recovery_count)` pair.
    unsafe {
        libisal_sys::ec_encode_data(
            shard_len as i32,
            original_count as i32,
            recovery_count as i32,
            g_tbls.as_ptr(),
            data_ptrs.as_ptr(),
            recovery_ptrs.as_mut_ptr(),
        );
    }
    recovery
}

fn decode_originals(
    provided_originals: &[(usize, &[u8])],
    provided_recoveries: &[(usize, &[u8])],
    original_count: usize,
    recovery_count: usize,
    shard_len: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    let total = original_count + recovery_count;
    let mut encode_matrix = vec![0u8; total * original_count];
    // SAFETY: `encode_matrix` is valid for `total * original_count` bytes.
    unsafe {
        libisal_sys::gf_gen_cauchy1_matrix(
            encode_matrix.as_mut_ptr(),
            total as i32,
            original_count as i32,
        );
    }

    let mut available = vec![false; total];
    let mut recover_srcs = Vec::with_capacity(original_count);
    let mut decode_index = Vec::with_capacity(original_count);

    for &(idx, shard) in provided_originals {
        available[idx] = true;
        recover_srcs.push(shard);
        decode_index.push(idx);
    }
    for &(idx, shard) in provided_recoveries {
        let absolute = original_count + idx;
        available[absolute] = true;
        recover_srcs.push(shard);
        decode_index.push(absolute);
    }
    if recover_srcs.len() < original_count {
        return Err(Error::NotEnoughChunks);
    }

    let missing: Vec<usize> = (0..total).filter(|idx| !available[*idx]).collect();
    let missing_originals: BTreeSet<usize> = missing
        .iter()
        .copied()
        .filter(|idx| *idx < original_count)
        .collect();

    let mut temp_matrix = vec![0u8; original_count * original_count];
    for (row, source_index) in decode_index.iter().take(original_count).copied().enumerate() {
        let src_row = &encode_matrix[source_index * original_count..(source_index + 1) * original_count];
        let dst_row =
            &mut temp_matrix[row * original_count..(row + 1) * original_count];
        dst_row.copy_from_slice(src_row);
    }

    let mut invert_matrix = vec![0u8; original_count * original_count];
    // SAFETY: both matrices are allocated as `original_count x original_count`.
    let invert_ok = unsafe {
        libisal_sys::gf_invert_matrix(
            temp_matrix.as_mut_ptr(),
            invert_matrix.as_mut_ptr(),
            original_count as i32,
        )
    } == 0;
    if !invert_ok {
        return Err(Error::Inconsistent);
    }

    let mut missing_decode_rows = Vec::with_capacity(missing.len() * original_count);
    for &missing_index in &missing {
        if missing_index < original_count {
            let row =
                &invert_matrix[missing_index * original_count..(missing_index + 1) * original_count];
            missing_decode_rows.extend_from_slice(row);
            continue;
        }

        let encode_row =
            &encode_matrix[missing_index * original_count..(missing_index + 1) * original_count];
        for column in 0..original_count {
            let mut value = 0u8;
            for entry in 0..original_count {
                // SAFETY: GF multiplication is pure for any byte pair.
                value ^= unsafe {
                    libisal_sys::gf_mul(
                        invert_matrix[entry * original_count + column],
                        encode_row[entry],
                    )
                };
            }
            missing_decode_rows.push(value);
        }
    }

    if missing_decode_rows.is_empty() {
        let mut originals = vec![vec![0u8; shard_len]; original_count];
        for &(idx, shard) in provided_originals {
            originals[idx].copy_from_slice(shard);
        }
        return Ok(originals);
    }

    let mut g_tbls = vec![0u8; original_count * missing.len() * 32];
    // SAFETY: buffers are sized per ISA-L requirements and `missing_decode_rows`
    // contains exactly `missing.len() * original_count` coefficients.
    unsafe {
        libisal_sys::ec_init_tables(
            original_count as i32,
            missing.len() as i32,
            missing_decode_rows.as_ptr(),
            g_tbls.as_mut_ptr(),
        );
    }

    let source_ptrs: Vec<*const u8> = recover_srcs.iter().take(original_count).map(|shard| shard.as_ptr()).collect();
    let mut recovered = vec![vec![0u8; shard_len]; missing.len()];
    let mut recovered_ptrs: Vec<*mut u8> = recovered.iter_mut().map(|shard| shard.as_mut_ptr()).collect();
    // SAFETY: all sources and outputs are valid for `shard_len` bytes and non-overlapping.
    unsafe {
        libisal_sys::ec_encode_data(
            shard_len as i32,
            original_count as i32,
            missing.len() as i32,
            g_tbls.as_ptr(),
            source_ptrs.as_ptr(),
            recovered_ptrs.as_mut_ptr(),
        );
    }

    let mut originals = vec![vec![0u8; shard_len]; original_count];
    for &(idx, shard) in provided_originals {
        originals[idx].copy_from_slice(shard);
    }
    for (missing_index, shard) in missing.into_iter().zip(recovered.into_iter()) {
        if missing_originals.contains(&missing_index) {
            originals[missing_index] = shard;
        }
    }
    Ok(originals)
}

fn encode<H: Hasher, S: Strategy>(
    total: u16,
    min: u16,
    data: Vec<u8>,
    strategy: &S,
) -> Result<(H::Digest, Vec<Chunk<H::Digest>>), Error> {
    let (k, m) = validate_counts(total, min)?;
    if data.len() > u32::MAX as usize {
        return Err(Error::InvalidDataLength(data.len()));
    }

    let (padded, shard_len) = prepare_data(&data, k);
    let originals: Vec<&[u8]> = padded.chunks(shard_len).collect();
    let recovery = encode_recovery(&originals, m);

    let originals: Bytes = padded.into();
    let recovery = recovery
        .into_iter()
        .flat_map(|shard| shard.into_iter())
        .collect::<Vec<_>>();
    let recoveries: Bytes = recovery.into();

    let n = total as usize;
    let shard_slices: Vec<Bytes> = (0..k)
        .map(|i| originals.slice(i * shard_len..(i + 1) * shard_len))
        .chain((0..m).map(|i| recoveries.slice(i * shard_len..(i + 1) * shard_len)))
        .collect();

    let mut builder = Builder::<H>::new(n);
    let shard_hashes = strategy.map_init_collect_vec(&shard_slices, H::new, |hasher, shard| {
        hasher.update(shard);
        hasher.finalize()
    });
    for hash in &shard_hashes {
        builder.add(hash);
    }
    let tree = builder.build();
    let root = tree.root();

    let mut chunks = Vec::with_capacity(n);
    for (i, shard) in shard_slices.into_iter().enumerate() {
        let proof = tree.proof(i as u32).map_err(|_| Error::InvalidProof)?;
        chunks.push(Chunk::new(shard, i as u16, proof));
    }
    Ok((root, chunks))
}

fn decode<'a, H: Hasher, S: Strategy>(
    total: u16,
    min: u16,
    root: &H::Digest,
    chunks: impl Iterator<Item = &'a CheckedChunk<H::Digest>>,
    strategy: &S,
) -> Result<Vec<u8>, Error> {
    let (k, m) = validate_counts(total, min)?;
    let n = total as usize;
    let mut chunks = chunks.peekable();
    let Some(first) = chunks.peek() else {
        return Err(Error::NotEnoughChunks);
    };

    let shard_len = first.shard.len();
    let mut shard_digests: Vec<Option<H::Digest>> = vec![None; n];
    let mut provided_originals: Vec<(usize, &[u8])> = Vec::new();
    let mut provided_recoveries: Vec<(usize, &[u8])> = Vec::new();
    let mut provided = 0usize;
    for chunk in chunks {
        provided += 1;
        if &chunk.root != root {
            return Err(Error::CommitmentMismatch);
        }
        let index = chunk.index;
        if index >= total {
            return Err(Error::InvalidIndex(index));
        }
        let digest_slot = &mut shard_digests[index as usize];
        if digest_slot.is_some() {
            return Err(Error::DuplicateIndex(index));
        }
        *digest_slot = Some(chunk.digest);
        if index < min {
            provided_originals.push((index as usize, chunk.shard.as_ref()));
        } else {
            provided_recoveries.push((index as usize - k, chunk.shard.as_ref()));
        }
    }
    if provided < k {
        return Err(Error::NotEnoughChunks);
    }

    let originals = decode_originals(&provided_originals, &provided_recoveries, k, m, shard_len)?;
    let original_refs: Vec<&[u8]> = originals.iter().map(Vec::as_slice).collect();
    let recoveries = encode_recovery(&original_refs, m);

    let mut shards: Vec<&[u8]> = originals.iter().map(Vec::as_slice).collect();
    shards.extend(recoveries.iter().map(Vec::as_slice));

    for (i, digest) in strategy.map_init_collect_vec(
        shard_digests
            .iter()
            .enumerate()
            .filter_map(|(i, digest)| digest.is_none().then_some(i)),
        H::new,
        |hasher, i| {
            hasher.update(shards[i]);
            (i, hasher.finalize())
        },
    ) {
        shard_digests[i] = Some(digest);
    }

    let mut builder = Builder::<H>::new(n);
    shard_digests
        .into_iter()
        .map(|digest| digest.expect("digest must be present for every shard"))
        .for_each(|digest| {
            builder.add(&digest);
        });
    let tree = builder.build();
    if tree.root() != *root {
        return Err(Error::Inconsistent);
    }

    extract_data(&shards, k).map_err(Into::into)
}

#[derive(Clone, Copy)]
pub struct ReedSolomonGf8<H> {
    _marker: PhantomData<H>,
}

impl<H> std::fmt::Debug for ReedSolomonGf8<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReedSolomonGf8").finish()
    }
}

impl<H: Hasher> Scheme for ReedSolomonGf8<H> {
    type Commitment = H::Digest;
    type Shard = Chunk<H::Digest>;
    type CheckedShard = CheckedChunk<H::Digest>;
    type Error = Error;

    fn encode(
        config: &Config,
        mut data: impl Buf,
        strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        let data: Vec<u8> = data.copy_to_bytes(data.remaining()).to_vec();
        encode::<H, _>(
            total_shards(config)?,
            config.minimum_shards.get(),
            data,
            strategy,
        )
    }

    fn check(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: &Self::Shard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        let total = total_shards(config)?;
        if index >= total {
            return Err(Error::InvalidIndex(index));
        }
        if shard.proof.leaf_count != u32::from(total) {
            return Err(Error::InvalidProof);
        }
        if shard.index != index {
            return Err(Error::InvalidIndex(shard.index));
        }
        shard
            .verify::<H>(shard.index, commitment)
            .ok_or(Error::InvalidProof)
    }

    fn decode<'a>(
        config: &Config,
        commitment: &Self::Commitment,
        shards: impl Iterator<Item = &'a Self::CheckedShard>,
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        decode::<H, _>(
            total_shards(config)?,
            config.minimum_shards.get(),
            commitment,
            shards,
            strategy,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_utils::NZU16;

    type RS = ReedSolomonGf8<Sha256>;
    const STRATEGY: Sequential = Sequential;

    #[test]
    fn test_roundtrip() {
        let config = Config {
            minimum_shards: NZU16!(3),
            extra_shards: NZU16!(2),
        };
        let data = b"isa-l gf8 shards";

        let (commitment, shards) = RS::encode(&config, data.as_slice(), &STRATEGY).unwrap();
        let checked = shards
            .iter()
            .enumerate()
            .take(config.minimum_shards.get() as usize)
            .map(|(i, shard)| RS::check(&config, &commitment, i as u16, shard).unwrap())
            .collect::<Vec<_>>();
        let decoded = RS::decode(&config, &commitment, checked.iter(), &STRATEGY).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_unsupported_counts() {
        let config = Config {
            minimum_shards: NZU16!(128),
            extra_shards: NZU16!(1),
        };
        let result = RS::encode(&config, [].as_slice(), &STRATEGY);
        assert!(matches!(
            result,
            Err(Error::UnsupportedShardCount {
                original_count: 128,
                recovery_count: 1,
            })
        ));
    }
}
