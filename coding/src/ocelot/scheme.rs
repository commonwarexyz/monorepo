//! Coding schemes over generic shard arithmetic.

use super::{
    code::{Decoder, Encoder, Impl, stripe_bytes},
    hash,
};
use crate::{CodecConfig, Config};
use bytes::{BufMut, Bytes};
use commonware_codec::{
    Buf, BufsMut, Encode, EncodeSize, FixedSize, RangeCfg, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{
    Digest, Hasher,
    transcript::{Summary, Transcript, Version},
};
use commonware_parallel::Strategy;
use commonware_storage::bmt::{self, Builder};
use rand_core::Rng as _;
use std::marker::PhantomData;
use thiserror::Error;

/// Number of checksum outputs used for early rejection of inconsistent shards.
const CHECKSUMS: usize = 16;
/// At most 65,535 originals, each carrying 16 two-byte checksum symbols.
const MAX_CHECKSUM_BYTES: usize = CHECKSUMS * 2 * u16::MAX as usize;
/// A systematic prefix needs at most one sibling per level in a 65,536-leaf tree.
const MAX_PREFIX_SIBLINGS: usize = u16::BITS as usize;

fn coefficient_count<I: Impl>(shard_len: usize) -> Result<usize, Error> {
    if !shard_len.is_multiple_of(I::ALIGN) {
        return Err(Error::InvalidData);
    }
    (shard_len / I::ALIGN)
        .checked_mul(CHECKSUMS)
        .ok_or(Error::InvalidData)
}

/// Errors returned by Ocelot coding schemes.
#[derive(Debug, Error)]
pub enum Error {
    /// The input cannot be represented by the encoded length prefix.
    #[error("data is too large: {0} bytes")]
    DataTooLarge(usize),
    /// The configured codeword does not fit in the field.
    #[error("invalid shard count")]
    InvalidShardCount,
    /// A shard index is outside the codeword or does not match the claimed index.
    #[error("invalid index: {0}")]
    InvalidIndex(u16),
    /// Strong-shard metadata is malformed or inconsistent with the commitment.
    #[error("invalid strong shard")]
    InvalidStrongShard,
    /// A weak shard has an invalid shape, proof, or checksum projection.
    #[error("invalid weak shard")]
    InvalidWeakShard,
    /// Fewer than the reconstruction threshold of distinct shards were supplied.
    #[error("insufficient shards {0} < {1}")]
    InsufficientShards(usize, usize),
    /// The same shard index was supplied more than once.
    #[error("duplicate shard index: {0}")]
    DuplicateIndex(u16),
    /// Checked data was produced under a different commitment.
    #[error("checked shard commitment does not match decode commitment")]
    CommitmentMismatch,
    /// Reconstructed originals, framing, length, or padding are invalid.
    #[error("invalid decoded data")]
    InvalidData,
    /// The underlying erasure decoder rejected the supplied shards.
    #[error("coding error: {0}")]
    Coding(#[from] super::code::Error),
    /// A Merkle inclusion proof could not be constructed.
    #[error("failed to create inclusion proof: {0}")]
    FailedToCreateInclusionProof(bmt::Error),
}

/// A shard sent by the encoder to one participant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrongShard<D: Digest> {
    data_bytes: u32,
    root: D,
    original_proof: bmt::Proof<D>,
    checksum: Bytes,
    weak: WeakShard<D>,
}

impl<D: Digest> Write for StrongShard<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.data_bytes.write(buf);
        self.root.write(buf);
        self.original_proof.write(buf);
        self.checksum.write(buf);
        self.weak.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.data_bytes.write(buf);
        self.root.write(buf);
        self.original_proof.write_bufs(buf);
        self.checksum.write_bufs(buf);
        self.weak.write_bufs(buf);
    }
}

impl<D: Digest> EncodeSize for StrongShard<D> {
    fn encode_size(&self) -> usize {
        self.data_bytes.encode_size()
            + self.root.encode_size()
            + self.original_proof.encode_size()
            + self.checksum.encode_size()
            + self.weak.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.data_bytes.encode_inline_size()
            + self.root.encode_inline_size()
            + self.original_proof.encode_inline_size()
            + self.checksum.encode_inline_size()
            + self.weak.encode_inline_size()
    }
}

impl<D: Digest> Read for StrongShard<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            data_bytes: ReadExt::read(buf)?,
            root: ReadExt::read(buf)?,
            original_proof: bmt::Proof {
                leaf_count: ReadExt::read(buf)?,
                siblings: Vec::read_range(buf, ..=MAX_PREFIX_SIBLINGS)?,
            },
            checksum: Bytes::read_cfg(buf, &RangeCfg::new(..=MAX_CHECKSUM_BYTES))?,
            weak: WeakShard::read_cfg(buf, cfg)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for StrongShard<D>
where
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            data_bytes: u.arbitrary()?,
            root: u.arbitrary()?,
            original_proof: u.arbitrary()?,
            checksum: u.arbitrary::<Vec<u8>>()?.into(),
            weak: u.arbitrary()?,
        })
    }
}

/// A shard forwarded between participants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeakShard<D: Digest> {
    shard: Bytes,
    index: u16,
    proof: bmt::Proof<D>,
}

impl<D: Digest> Write for WeakShard<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.shard.write(buf);
        self.index.write(buf);
        self.proof.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.shard.write_bufs(buf);
        self.index.write(buf);
        self.proof.write(buf);
    }
}

impl<D: Digest> EncodeSize for WeakShard<D> {
    fn encode_size(&self) -> usize {
        self.shard.encode_size() + self.index.encode_size() + self.proof.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.shard.encode_inline_size() + self.index.encode_size() + self.proof.encode_size()
    }
}

impl<D: Digest> Read for WeakShard<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            shard: Bytes::read_cfg(buf, &RangeCfg::new(..=cfg.maximum_shard_size))?,
            index: ReadExt::read(buf)?,
            proof: bmt::Proof::read_cfg(buf, &1)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for WeakShard<D>
where
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            shard: u.arbitrary::<Vec<u8>>()?.into(),
            index: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

/// Data derived from a participant's strong shard for checking forwarded shards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckingData<D: Digest> {
    namespace: &'static [u8],
    commitment: Summary,
    config: Config,
    data_bytes: u32,
    root: D,
    original_proof: bmt::Proof<D>,
    coefficients: Bytes,
    encoded_checksum: Vec<Bytes>,
    shard_len: usize,
}

/// A shard whose Merkle proof has been checked by the basic scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicCheckedShard<D: Digest> {
    namespace: &'static [u8],
    config: Config,
    commitment: D,
    index: u16,
    shard: Bytes,
    digest: D,
}

/// A shard whose Merkle proof and checksum projection have been checked.
#[derive(Clone, Debug)]
pub struct CheckedShard<D: Digest> {
    commitment: Summary,
    index: u16,
    shard: Bytes,
    digest: D,
}

/// A shard used by the basic scheme.
pub type Shard<D> = WeakShard<D>;

struct Encoding<D: Digest> {
    data_bytes: u32,
    shard_len: usize,
    originals: Bytes,
    root: D,
    original_proof: bmt::Proof<D>,
    shards: Vec<WeakShard<D>>,
}

enum ShardData<'a> {
    Borrowed(&'a [u8]),
    Recovered(Vec<u8>),
}

impl AsRef<[u8]> for ShardData<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(shard) => shard,
            Self::Recovered(shard) => shard,
        }
    }
}

struct Selection<'a, M> {
    originals: Vec<Option<&'a [u8]>>,
    recovery: Vec<Option<&'a [u8]>>,
    metadata: Vec<Option<M>>,
    shard_len: usize,
    all_originals: bool,
}

struct Recovered<'a, M> {
    originals: Vec<ShardData<'a>>,
    recovery: Vec<Option<ShardData<'a>>>,
    metadata: Vec<Option<M>>,
    shard_len: usize,
    all_originals: bool,
}

#[derive(Clone, Copy)]
enum RecoveryMode {
    Originals,
    FullCodeword,
}

fn topology<I: Impl>(config: &Config) -> Result<(usize, usize, usize), Error> {
    let original = usize::from(config.minimum_shards.get());
    let recovery = usize::from(config.extra_shards.get());
    let padded_recovery = recovery
        .checked_next_power_of_two()
        .ok_or(Error::InvalidShardCount)?;
    if original > I::ORDER || padded_recovery > I::ORDER - original {
        return Err(Error::InvalidShardCount);
    }
    Ok((original, recovery, original + recovery))
}

fn shard_len<I: Impl>(data_bytes: usize, original: usize) -> Result<usize, Error> {
    let prefixed = data_bytes
        .checked_add(u32::SIZE)
        .ok_or(Error::InvalidData)?;
    let unaligned = prefixed.div_ceil(original);
    unaligned
        .checked_next_multiple_of(I::ALIGN)
        .ok_or(Error::InvalidData)
}

fn encode_codeword<I: Impl, H: Hasher>(
    imp: I,
    config: &Config,
    mut data: impl bytes::Buf,
    strategy: &impl Strategy,
) -> Result<Encoding<H::Digest>, Error> {
    let (original_count, recovery_count, total) = topology::<I>(config)?;
    let data_len = data.remaining();
    let data_bytes = u32::try_from(data_len).map_err(|_| Error::DataTooLarge(data_len))?;
    let shard_len = shard_len::<I>(data_len, original_count)?;
    let padded_len = original_count
        .checked_mul(shard_len)
        .ok_or(Error::InvalidData)?;
    let recovery_len = recovery_count
        .checked_mul(shard_len)
        .ok_or(Error::InvalidData)?;
    let mut padded = vec![0; padded_len];
    padded[..u32::SIZE].copy_from_slice(&data_bytes.to_be_bytes());
    data.copy_to_slice(&mut padded[u32::SIZE..u32::SIZE + data_len]);
    let originals = Bytes::from(padded);
    let original_refs: Vec<_> = originals.chunks_exact(shard_len).collect();
    let mut recovery = vec![0; recovery_len];
    let mut recovery_shards: Vec<_> = recovery.chunks_exact_mut(shard_len).collect();
    Encoder::new(imp).encode_into(&original_refs, &mut recovery_shards, strategy);
    let recovery = Bytes::from(recovery);
    let shard_bytes: Vec<Bytes> = (0..original_count)
        .map(|index| originals.slice(index * shard_len..(index + 1) * shard_len))
        .chain(
            (0..recovery_count)
                .map(|index| recovery.slice(index * shard_len..(index + 1) * shard_len)),
        )
        .collect();

    let digests = hash::shards::<H>(&shard_bytes, strategy);
    let mut builder = Builder::<H>::new(total);
    for digest in &digests {
        builder.add(digest);
    }
    let tree = builder.build();
    let root = tree.root();
    let original_proof = tree
        .range_proof(0, original_count as u32 - 1)
        .map_err(Error::FailedToCreateInclusionProof)?;
    let shards = shard_bytes
        .into_iter()
        .enumerate()
        .map(|(index, shard)| {
            let index = index as u16;
            let proof = tree
                .proof(u32::from(index))
                .map_err(Error::FailedToCreateInclusionProof)?;
            Ok::<_, Error>(WeakShard {
                shard,
                index,
                proof,
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(Encoding {
        data_bytes,
        shard_len,
        originals,
        root,
        original_proof,
        shards,
    })
}

fn validate_shard<I: Impl, D: Digest>(
    config: &Config,
    index: u16,
    shard: &WeakShard<D>,
    expected_shard_len: Option<usize>,
) -> Result<(), Error> {
    let (_, _, total) = topology::<I>(config)?;
    if usize::from(index) >= total {
        return Err(Error::InvalidIndex(index));
    }
    if shard.index != index {
        return Err(Error::InvalidIndex(shard.index));
    }
    if shard.proof.leaf_count != total as u32
        || expected_shard_len.is_some_and(|expected| shard.shard.len() != expected)
        || !shard.shard.len().is_multiple_of(I::ALIGN)
    {
        return Err(Error::InvalidWeakShard);
    }
    Ok(())
}

fn verify_shard_proof<H: Hasher>(
    root: &H::Digest,
    index: u16,
    shard: &WeakShard<H::Digest>,
    strategy: &impl Strategy,
) -> Result<H::Digest, Error> {
    let digest = hash::shard::<H>(&shard.shard, strategy);
    shard
        .proof
        .verify_element_inclusion::<H>(&digest, u32::from(index), root)
        .map_err(|_| Error::InvalidWeakShard)?;
    Ok(digest)
}

fn verify_shard<I: Impl, H: Hasher>(
    config: &Config,
    root: &H::Digest,
    index: u16,
    shard: &WeakShard<H::Digest>,
    expected_shard_len: Option<usize>,
    strategy: &impl Strategy,
) -> Result<H::Digest, Error> {
    validate_shard::<I, _>(config, index, shard, expected_shard_len)?;
    verify_shard_proof::<H>(root, index, shard, strategy)
}

fn select_shards<'a, I: Impl, T, M>(
    config: &Config,
    expected_shard_len: Option<usize>,
    shards: impl Iterator<Item = &'a T>,
    mut inspect: impl FnMut(&'a T) -> Result<(u16, &'a [u8], M), Error>,
) -> Result<Selection<'a, M>, Error>
where
    T: 'a,
{
    let (original_count, recovery_count, total) = topology::<I>(config)?;
    let mut originals = vec![None; original_count];
    let mut recovery = vec![None; recovery_count];
    let mut metadata: Vec<Option<M>> = (0..total).map(|_| None).collect();
    let mut actual_shard_len = expected_shard_len;
    let mut present = 0usize;
    for checked in shards {
        let (index, shard, meta) = inspect(checked)?;
        let index_usize = usize::from(index);
        if index_usize >= total {
            return Err(Error::InvalidIndex(index));
        }
        let width = *actual_shard_len.get_or_insert(shard.len());
        if shard.len() != width || !width.is_multiple_of(I::ALIGN) {
            return Err(Error::InvalidWeakShard);
        }
        if metadata[index_usize].replace(meta).is_some() {
            return Err(Error::DuplicateIndex(index));
        }
        let slot = if index_usize < original_count {
            &mut originals[index_usize]
        } else {
            &mut recovery[index_usize - original_count]
        };
        *slot = Some(shard);
        present += 1;
    }
    if present < original_count {
        return Err(Error::InsufficientShards(present, original_count));
    }
    let originals_present = originals.iter().flatten().count();
    let all_originals = originals_present == original_count;
    if !all_originals {
        let mut needed = original_count - originals_present;
        for (index, slot) in recovery.iter_mut().enumerate() {
            if slot.is_none() {
                continue;
            }
            if needed > 0 {
                needed -= 1;
            } else {
                *slot = None;
                metadata[original_count + index] = None;
            }
        }
        debug_assert_eq!(needed, 0);
    }
    Ok(Selection {
        originals,
        recovery,
        metadata,
        shard_len: actual_shard_len.unwrap_or(0),
        all_originals,
    })
}

fn recover<'a, I: Impl, M>(
    imp: I,
    selection: Selection<'a, M>,
    mode: RecoveryMode,
    strategy: &impl Strategy,
) -> Result<Recovered<'a, M>, Error> {
    let (restored_originals, restored_recovery) = if selection.all_originals {
        (Vec::new(), Vec::new())
    } else {
        match mode {
            RecoveryMode::Originals => (
                Decoder::new(imp).decode(&selection.originals, &selection.recovery, strategy)?,
                Vec::new(),
            ),
            RecoveryMode::FullCodeword => Decoder::new(imp).decode_with_recovery(
                &selection.originals,
                &selection.recovery,
                strategy,
            )?,
        }
    };

    let mut originals: Vec<Option<ShardData<'a>>> = selection
        .originals
        .into_iter()
        .map(|shard| shard.map(ShardData::Borrowed))
        .collect();
    for (index, shard) in restored_originals {
        let Some(slot) = originals.get_mut(index) else {
            return Err(Error::InvalidData);
        };
        if slot.replace(ShardData::Recovered(shard)).is_some() {
            return Err(Error::InvalidData);
        }
    }
    let originals = originals
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::InvalidData)?;

    let mut recovery: Vec<Option<ShardData<'a>>> = selection
        .recovery
        .into_iter()
        .map(|shard| shard.map(ShardData::Borrowed))
        .collect();
    for (index, shard) in restored_recovery {
        let Some(slot) = recovery.get_mut(index) else {
            return Err(Error::InvalidData);
        };
        if slot.replace(ShardData::Recovered(shard)).is_some() {
            return Err(Error::InvalidData);
        }
    }
    if matches!(mode, RecoveryMode::FullCodeword)
        && !selection.all_originals
        && recovery.iter().any(Option::is_none)
    {
        return Err(Error::InvalidData);
    }
    Ok(Recovered {
        originals,
        recovery,
        metadata: selection.metadata,
        shard_len: selection.shard_len,
        all_originals: selection.all_originals,
    })
}

fn extract_data<I: Impl>(
    originals: &[ShardData<'_>],
    shard_width: usize,
    expected_data_bytes: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let original_count = originals.len();
    let total_len = original_count
        .checked_mul(shard_width)
        .ok_or(Error::InvalidData)?;
    if total_len < u32::SIZE {
        return Err(Error::InvalidData);
    }

    let mut prefix = [0; u32::SIZE];
    let mut prefix_len = 0usize;
    for shard in originals {
        if prefix_len == u32::SIZE {
            break;
        }
        let shard = shard.as_ref();
        let read = (u32::SIZE - prefix_len).min(shard.len());
        prefix[prefix_len..prefix_len + read].copy_from_slice(&shard[..read]);
        prefix_len += read;
    }
    let encoded_len = u32::from_be_bytes(prefix);
    if expected_data_bytes.is_some_and(|expected| encoded_len != expected)
        || encoded_len as usize > total_len - u32::SIZE
        || shard_len::<I>(encoded_len as usize, original_count)? != shard_width
    {
        return Err(Error::InvalidData);
    }

    let mut data = Vec::with_capacity(encoded_len as usize);
    let mut prefix_left = u32::SIZE;
    let mut data_left = encoded_len as usize;
    for shard in originals {
        let shard = shard.as_ref();
        if prefix_left >= shard.len() {
            prefix_left -= shard.len();
            continue;
        }
        let payload = &shard[prefix_left..];
        let copy = data_left.min(payload.len());
        data.extend_from_slice(&payload[..copy]);
        data_left -= copy;
        if payload[copy..].iter().any(|&byte| byte != 0) {
            return Err(Error::InvalidData);
        }
        prefix_left = 0;
    }
    if data_left != 0 {
        return Err(Error::InvalidData);
    }
    Ok(data)
}

fn verify_codeword<H: Hasher>(
    root: &H::Digest,
    mut digests: Vec<Option<H::Digest>>,
    originals: &[&[u8]],
    recovery: &[&[u8]],
    strategy: &impl Strategy,
) -> Result<(), Error> {
    let original_count = originals.len();
    let missing: Vec<_> = digests
        .iter()
        .enumerate()
        .filter_map(|(index, digest)| {
            digest.is_none().then_some((
                index,
                if index < original_count {
                    originals[index]
                } else {
                    recovery[index - original_count]
                },
            ))
        })
        .collect();
    let shards: Vec<_> = missing.iter().map(|(_, shard)| *shard).collect();
    for ((index, _), digest) in missing
        .into_iter()
        .zip(hash::shards::<H>(&shards, strategy))
    {
        digests[index] = Some(digest);
    }
    let mut builder = Builder::<H>::new(digests.len());
    for digest in digests {
        builder.add(&digest.ok_or(Error::InvalidData)?);
    }
    if builder.build().root() != *root {
        return Err(Error::InvalidData);
    }
    Ok(())
}

/// Reed-Solomon coding using `I` for arithmetic and `H` for commitments.
pub struct OcelotX<I: Impl, H> {
    imp: I,
    _marker: PhantomData<H>,
}

impl<I: Impl, H: Hasher> OcelotX<I, H> {
    /// Use the supplied arithmetic implementation for coding operations.
    pub const fn new(imp: I) -> Self {
        const {
            assert!(I::ALIGN > 0);
        }
        Self {
            imp,
            _marker: PhantomData,
        }
    }

    /// Encode the payload and commit to the complete codeword.
    #[allow(clippy::type_complexity)]
    pub fn encode(
        &self,
        config: &Config,
        data: impl bytes::Buf,
        strategy: &impl Strategy,
    ) -> Result<(H::Digest, Vec<Shard<H::Digest>>), Error> {
        let encoding = encode_codeword::<I, H>(self.imp, config, data, strategy)?;
        Ok((encoding.root, encoding.shards))
    }

    /// Check a shard's shape and inclusion in the committed codeword.
    pub fn check(
        &self,
        config: &Config,
        commitment: &H::Digest,
        index: u16,
        shard: &Shard<H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<BasicCheckedShard<H::Digest>, Error> {
        let digest = verify_shard::<I, H>(config, commitment, index, shard, None, strategy)?;
        Ok(BasicCheckedShard {
            namespace: I::NAMESPACE,
            config: *config,
            commitment: *commitment,
            index,
            shard: shard.shard.clone(),
            digest,
        })
    }

    /// Recover the payload and verify the complete canonical codeword.
    pub fn decode<'a>(
        &self,
        config: &Config,
        commitment: &H::Digest,
        shards: impl Iterator<Item = &'a BasicCheckedShard<H::Digest>>,
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Error> {
        let selection = select_shards::<I, _, _>(config, None, shards, |checked| {
            if checked.namespace != I::NAMESPACE
                || checked.config != *config
                || checked.commitment != *commitment
            {
                return Err(Error::CommitmentMismatch);
            }
            Ok((checked.index, checked.shard.as_ref(), checked.digest))
        })?;
        let recovered = recover(self.imp, selection, RecoveryMode::FullCodeword, strategy)?;
        let data = extract_data::<I>(&recovered.originals, recovered.shard_len, None)?;
        let originals: Vec<&[u8]> = recovered.originals.iter().map(AsRef::as_ref).collect();
        let mut canonical_recovery;
        let recovery: Vec<&[u8]> = if recovered.all_originals {
            let recovery_len = recovered
                .recovery
                .len()
                .checked_mul(recovered.shard_len)
                .ok_or(Error::InvalidData)?;
            canonical_recovery = vec![0; recovery_len];
            let mut recovery: Vec<_> = canonical_recovery
                .chunks_exact_mut(recovered.shard_len)
                .collect();
            Encoder::new(self.imp).encode_into(&originals, &mut recovery, strategy);
            let recovery: Vec<_> = recovery.into_iter().map(|shard| &*shard).collect();
            for (provided, canonical) in recovered.recovery.iter().zip(&recovery) {
                if provided
                    .as_ref()
                    .is_some_and(|provided| provided.as_ref() != *canonical)
                {
                    return Err(Error::InvalidData);
                }
            }
            recovery
        } else {
            recovered
                .recovery
                .iter()
                .map(|shard| shard.as_ref().map(AsRef::as_ref).ok_or(Error::InvalidData))
                .collect::<Result<_, _>>()?
        };
        verify_codeword::<H>(
            commitment,
            recovered.metadata,
            &originals,
            &recovery,
            strategy,
        )?;
        Ok(data)
    }
}

/// Hinted Reed-Solomon coding with Fiat-Shamir checksum projections.
///
/// `CHECKSUM_BYTES` must hold exactly [`CHECKSUMS`] symbols of `I`.
pub struct OcelotHintedX<I: Impl, H, const CHECKSUM_BYTES: usize> {
    imp: I,
    _marker: PhantomData<H>,
}

impl<I: Impl, H: Hasher, const CHECKSUM_BYTES: usize> OcelotHintedX<I, H, CHECKSUM_BYTES> {
    /// Use the supplied arithmetic implementation for coding operations.
    pub const fn new(imp: I) -> Self {
        const {
            assert!(I::ALIGN > 0);
            assert!(CHECKSUM_BYTES == CHECKSUMS * I::ALIGN);
        }
        Self {
            imp,
            _marker: PhantomData,
        }
    }

    fn transcript(
        namespace: &[u8],
        config: &Config,
        data_bytes: u32,
        root: &H::Digest,
        original_proof: &bmt::Proof<H::Digest>,
    ) -> Transcript {
        let mut transcript = Transcript::new(I::NAMESPACE, Version::V1);
        transcript.commit(namespace);
        transcript.commit(config.encode());
        transcript.commit(data_bytes.encode());
        transcript.commit(root.encode());
        transcript.commit(original_proof.encode());
        transcript
    }

    fn coefficients(transcript: &Transcript, shard_len: usize) -> Result<Bytes, Error> {
        let len = coefficient_count::<I>(shard_len)?;
        let mut coefficients = vec![0; len];
        transcript
            .noise(b"checksum coefficients")
            .fill_bytes(&mut coefficients);
        Ok(coefficients.into())
    }

    fn checksum(
        &self,
        shards: &[&[u8]],
        coefficients: &[u8],
        strategy: &impl Strategy,
    ) -> Result<Bytes, Error> {
        let total_len = shards
            .len()
            .checked_mul(CHECKSUM_BYTES)
            .ok_or(Error::InvalidData)?;
        let shard_len = shards.first().map_or(0, |shard| shard.len());
        if shards.iter().any(|shard| shard.len() != shard_len)
            || coefficients.len() != coefficient_count::<I>(shard_len)?
        {
            return Err(Error::InvalidData);
        }
        if shard_len == 0 {
            return Ok(vec![0; total_len].into());
        }

        let stripe_bytes = stripe_bytes::<I>();
        let stripes = shard_len.div_ceil(stripe_bytes);
        let tiles = shards
            .len()
            .checked_mul(stripes)
            .ok_or(Error::InvalidData)?;
        let checksum = strategy.fold_init(
            0..tiles,
            || [0; CHECKSUM_BYTES],
            || vec![0; total_len],
            |mut checksum, partial, tile| {
                let shard = tile / stripes;
                let start = (tile % stripes) * stripe_bytes;
                let end = start + stripe_bytes.min(shard_len - start);
                self.imp
                    .checksum_range(shards[shard], coefficients, start..end, partial);
                let offset = shard * CHECKSUM_BYTES;
                self.imp
                    .add_into(&mut checksum[offset..offset + CHECKSUM_BYTES], partial);
                checksum
            },
            |mut a, b| {
                self.imp.add_into(&mut a, &b);
                a
            },
        );
        Ok(checksum.into())
    }

    fn derive_checking_data(
        &self,
        namespace: &[u8],
        config: &Config,
        commitment: &Summary,
        shard: &StrongShard<H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<CheckingData<H::Digest>, Error> {
        let (original, recovery, total) = topology::<I>(config)?;
        let shard_len = shard_len::<I>(shard.data_bytes as usize, original)?;
        let expected_checksum_len = original
            .checked_mul(CHECKSUM_BYTES)
            .ok_or(Error::InvalidStrongShard)?;
        if shard.weak.shard.len() != shard_len
            || shard.checksum.len() != expected_checksum_len
            || shard.original_proof.leaf_count != total as u32
            || shard.original_proof.siblings.len() > MAX_PREFIX_SIBLINGS
        {
            return Err(Error::InvalidStrongShard);
        }
        let mut transcript = Self::transcript(
            namespace,
            config,
            shard.data_bytes,
            &shard.root,
            &shard.original_proof,
        );
        let coefficients = Self::coefficients(&transcript, shard_len)?;
        transcript.commit(shard.checksum.clone());
        let expected_commitment = transcript.summarize();
        if expected_commitment != *commitment {
            return Err(Error::InvalidStrongShard);
        }

        let (checksum_rows, remainder) = shard.checksum.as_chunks::<CHECKSUM_BYTES>();
        debug_assert!(remainder.is_empty());
        let originals: Vec<&[u8]> = checksum_rows
            .iter()
            .map(<[u8; CHECKSUM_BYTES]>::as_slice)
            .collect();
        let encoded = Encoder::new(self.imp).encode(&originals, recovery, strategy);
        let encoded_checksum = originals
            .into_iter()
            .map(Bytes::copy_from_slice)
            .chain(encoded.into_iter().map(Bytes::from))
            .collect();
        Ok(CheckingData {
            namespace: I::NAMESPACE,
            commitment: expected_commitment,
            config: *config,
            data_bytes: shard.data_bytes,
            root: shard.root,
            original_proof: shard.original_proof.clone(),
            coefficients,
            encoded_checksum,
            shard_len,
        })
    }

    fn check_weak(
        &self,
        commitment: &Summary,
        checking_data: &CheckingData<H::Digest>,
        index: u16,
        weak: &WeakShard<H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<CheckedShard<H::Digest>, Error> {
        if checking_data.namespace != I::NAMESPACE || checking_data.commitment != *commitment {
            return Err(Error::CommitmentMismatch);
        }
        validate_shard::<I, _>(
            &checking_data.config,
            index,
            weak,
            Some(checking_data.shard_len),
        )?;
        let checksum = self.checksum(&[&weak.shard], &checking_data.coefficients, strategy)?;
        if checksum != checking_data.encoded_checksum[usize::from(index)] {
            return Err(Error::InvalidWeakShard);
        }
        let digest = verify_shard_proof::<H>(&checking_data.root, index, weak, strategy)?;
        Ok(CheckedShard {
            commitment: *commitment,
            index,
            shard: weak.shard.clone(),
            digest,
        })
    }

    /// Encode the payload with checksums and a proof of its systematic prefix.
    #[allow(clippy::type_complexity)]
    pub fn encode(
        &self,
        namespace: &[u8],
        config: &Config,
        data: impl bytes::Buf,
        strategy: &impl Strategy,
    ) -> Result<(Summary, Vec<StrongShard<H::Digest>>), Error> {
        let encoding = encode_codeword::<I, H>(self.imp, config, data, strategy)?;
        let originals: Vec<_> = encoding
            .originals
            .chunks_exact(encoding.shard_len)
            .collect();
        let root = encoding.root;
        let data_bytes = encoding.data_bytes;
        let shard_len = encoding.shard_len;
        let original_proof = encoding.original_proof;
        let mut transcript =
            Self::transcript(namespace, config, data_bytes, &root, &original_proof);
        let coefficients = Self::coefficients(&transcript, shard_len)?;
        let checksum = self.checksum(&originals, &coefficients, strategy)?;
        transcript.commit(checksum.clone());
        let commitment = transcript.summarize();

        let strong = encoding
            .shards
            .into_iter()
            .map(|weak| StrongShard {
                data_bytes,
                root,
                original_proof: original_proof.clone(),
                checksum: checksum.clone(),
                weak,
            })
            .collect();
        Ok((commitment, strong))
    }

    /// Derive checking data and check the participant's shard before forwarding it.
    #[allow(clippy::type_complexity)]
    pub fn weaken(
        &self,
        namespace: &[u8],
        config: &Config,
        commitment: &Summary,
        index: u16,
        shard: StrongShard<H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<
        (
            CheckingData<H::Digest>,
            CheckedShard<H::Digest>,
            WeakShard<H::Digest>,
        ),
        Error,
    > {
        let checking_data =
            self.derive_checking_data(namespace, config, commitment, &shard, strategy)?;
        let weak = shard.weak;
        let checked = self.check_weak(commitment, &checking_data, index, &weak, strategy)?;
        Ok((checking_data, checked, weak))
    }

    /// Check a forwarded shard against its Merkle commitment and checksum.
    pub fn check(
        &self,
        config: &Config,
        commitment: &Summary,
        checking_data: &CheckingData<H::Digest>,
        index: u16,
        weak: WeakShard<H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<CheckedShard<H::Digest>, Error> {
        if checking_data.config != *config {
            return Err(Error::CommitmentMismatch);
        }
        self.check_weak(commitment, checking_data, index, &weak, strategy)
    }

    /// Recover the payload, proving inclusion of any reconstructed originals.
    pub fn decode<'a>(
        &self,
        config: &Config,
        commitment: &Summary,
        checking_data: CheckingData<H::Digest>,
        shards: impl Iterator<Item = &'a CheckedShard<H::Digest>>,
        strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Error> {
        if checking_data.namespace != I::NAMESPACE
            || checking_data.commitment != *commitment
            || checking_data.config != *config
        {
            return Err(Error::CommitmentMismatch);
        }
        let selection =
            select_shards::<I, _, _>(config, Some(checking_data.shard_len), shards, |shard| {
                if shard.commitment != *commitment {
                    return Err(Error::CommitmentMismatch);
                }
                Ok((shard.index, shard.shard.as_ref(), shard.digest))
            })?;
        let recovered = recover(self.imp, selection, RecoveryMode::Originals, strategy)?;
        if !recovered.all_originals {
            let missing: Vec<_> = recovered
                .originals
                .iter()
                .filter_map(|shard| match shard {
                    ShardData::Recovered(shard) => Some(shard.as_slice()),
                    ShardData::Borrowed(_) => None,
                })
                .collect();
            let mut fresh = hash::shards::<H>(&missing, strategy).into_iter();
            let digests = recovered
                .originals
                .iter()
                .zip(&recovered.metadata)
                .map(|(shard, digest)| {
                    match shard {
                        ShardData::Borrowed(_) => *digest,
                        ShardData::Recovered(_) => fresh.next(),
                    }
                    .ok_or(Error::InvalidData)
                })
                .collect::<Result<Vec<_>, _>>()?;
            checking_data
                .original_proof
                .verify_range_inclusion::<H>(0, &digests, &checking_data.root)
                .map_err(|_| Error::InvalidData)?;
        }
        extract_data::<I>(
            &recovered.originals,
            recovered.shard_len,
            Some(checking_data.data_bytes),
        )
    }
}

/// Fuzz plans for Ocelot coding schemes.
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use crate::ocelot::{Impl8, Impl16, kernel::portable::Portable};
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_utils::NZU16;
    use std::{cell::Cell, num::NonZeroU16};

    const STRATEGY: Sequential = Sequential;
    const FUZZ_MAX_DATA_LEN: usize = 256;

    type Basic = OcelotX<Impl8<Portable>, Sha256>;

    /// A bounded property check for an Ocelot coding scheme.
    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        /// Check basic-scheme roundtrips and rejection paths.
        Basic,
        /// Check hinted-scheme roundtrips and rejection paths.
        Hinted,
    }

    impl Plan {
        /// Run this fuzz plan using additional structured input from `u`.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Basic => fuzz_basic(u),
                Self::Hinted => fuzz_hinted(u),
            }
        }
    }

    fn config(u: &mut Unstructured<'_>) -> arbitrary::Result<(Config, usize, usize)> {
        let original = u.int_in_range(2u16..=4)?;
        let recovery = u.int_in_range(original..=6)?;
        Ok((
            Config {
                minimum_shards: NonZeroU16::new(original).unwrap(),
                extra_shards: NonZeroU16::new(recovery).unwrap(),
            },
            usize::from(original),
            usize::from(recovery),
        ))
    }

    fn data(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
        let len = u.int_in_range(0..=FUZZ_MAX_DATA_LEN)?;
        Ok(u.bytes(len)?.to_vec())
    }

    fn shuffled_indices(
        u: &mut Unstructured<'_>,
        total: usize,
        count: usize,
    ) -> arbitrary::Result<Vec<usize>> {
        let mut indices: Vec<_> = (0..total).collect();
        for i in 0..count {
            let selected = i + u.choose_index(total - i)?;
            indices.swap(i, selected);
        }
        indices.truncate(count);
        Ok(indices)
    }

    fn prove_codeword(
        codeword: Vec<Vec<u8>>,
    ) -> (
        <Sha256 as Hasher>::Digest,
        Vec<WeakShard<<Sha256 as Hasher>::Digest>>,
    ) {
        let mut builder = Builder::<Sha256>::new(codeword.len());
        for shard in &codeword {
            builder.add(&hash::shard::<Sha256>(shard, &STRATEGY));
        }
        let tree = builder.build();
        let root = tree.root();
        let shards = codeword
            .into_iter()
            .enumerate()
            .map(|(index, shard)| WeakShard {
                shard: shard.into(),
                index: index as u16,
                proof: tree.proof(index as u32).unwrap(),
            })
            .collect();
        (root, shards)
    }

    fn check_basic(
        scheme: &Basic,
        config: &Config,
        root: &<Sha256 as Hasher>::Digest,
        shards: &[WeakShard<<Sha256 as Hasher>::Digest>],
    ) -> Vec<BasicCheckedShard<<Sha256 as Hasher>::Digest>> {
        shards
            .iter()
            .enumerate()
            .map(|(index, shard)| {
                scheme
                    .check(config, root, index as u16, shard, &STRATEGY)
                    .unwrap()
            })
            .collect()
    }

    fn assert_basic_decode(
        scheme: &Basic,
        config: &Config,
        root: &<Sha256 as Hasher>::Digest,
        checked: &[BasicCheckedShard<<Sha256 as Hasher>::Digest>],
        indices: &[usize],
        expected: &[u8],
    ) {
        let decoded = scheme
            .decode(
                config,
                root,
                indices.iter().map(|&index| &checked[index]),
                &STRATEGY,
            )
            .unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(
            scheme
                .encode(config, decoded.as_slice(), &STRATEGY)
                .unwrap()
                .0,
            *root,
            "decode accepted a non-canonical commitment"
        );
    }

    fn fuzz_basic(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let (config, original, recovery) = config(u)?;
        let data = data(u)?;
        let total = original + recovery;
        let scheme = Basic::new(Impl8::new(Portable));
        let (root, shards) = scheme.encode(&config, data.as_slice(), &STRATEGY).unwrap();
        let checked = check_basic(&scheme, &config, &root, &shards);

        let random_count = u.int_in_range(original..=total)?;
        let random = shuffled_indices(u, total, random_count)?;
        let systematic: Vec<_> = (0..original).collect();
        let mixed: Vec<_> = (1..original).chain([original]).collect();
        let recovery_only: Vec<_> = (original..2 * original).collect();
        let all_reversed: Vec<_> = (0..total).rev().collect();
        for indices in [&systematic, &mixed, &recovery_only, &all_reversed, &random] {
            assert_basic_decode(&scheme, &config, &root, &checked, indices, &data);
        }

        assert!(matches!(
            scheme.decode(&config, &root, checked.iter().take(original - 1), &STRATEGY),
            Err(Error::InsufficientShards(_, _))
        ));
        assert!(matches!(
            scheme.decode(
                &config,
                &root,
                [&checked[0], &checked[0]].into_iter(),
                &STRATEGY
            ),
            Err(Error::DuplicateIndex(0))
        ));

        let target = u.choose_index(total)?;
        let mut corrupt = shards[target].clone();
        let offset = u.choose_index(corrupt.shard.len())?;
        let mut bytes = corrupt.shard.to_vec();
        bytes[offset] ^= 1;
        corrupt.shard = bytes.into();
        assert!(matches!(
            scheme.check(&config, &root, target as u16, &corrupt, &STRATEGY),
            Err(Error::InvalidWeakShard)
        ));

        let mut wrong_proof = shards[target].clone();
        wrong_proof.proof.siblings[0] = Sha256::hash(&[b"corrupt proof".as_slice()]);
        assert!(matches!(
            scheme.check(&config, &root, target as u16, &wrong_proof, &STRATEGY),
            Err(Error::InvalidWeakShard)
        ));
        assert!(matches!(
            scheme.check(&config, &root, total as u16, &shards[target], &STRATEGY),
            Err(Error::InvalidIndex(_))
        ));
        let mut wrong_index = shards[target].clone();
        wrong_index.index = ((target + 1) % total) as u16;
        assert!(matches!(
            scheme.check(&config, &root, target as u16, &wrong_index, &STRATEGY),
            Err(Error::InvalidIndex(_))
        ));

        let mut wrong_namespace = checked[0].clone();
        wrong_namespace.namespace = b"other field";
        let mut wrong_config = checked[0].clone();
        wrong_config.config = Config {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(1),
        };
        let mut wrong_commitment = checked[0].clone();
        wrong_commitment.commitment = Sha256::hash(&[b"other commitment".as_slice()]);
        for mismatched in [&wrong_namespace, &wrong_config, &wrong_commitment] {
            assert!(matches!(
                scheme.decode(
                    &config,
                    &root,
                    [mismatched]
                        .into_iter()
                        .chain(checked.iter().skip(1).take(original - 1)),
                    &STRATEGY
                ),
                Err(Error::CommitmentMismatch)
            ));
        }

        // A committed recovery shard must agree with the systematic codeword.
        let honest: Vec<Vec<u8>> = shards.iter().map(|shard| shard.shard.to_vec()).collect();
        let mut bad_with_originals = honest.clone();
        bad_with_originals[original][0] ^= 1;
        let (bad_root, bad_shards) = prove_codeword(bad_with_originals);
        let bad_checked = check_basic(&scheme, &config, &bad_root, &bad_shards);
        assert!(matches!(
            scheme.decode(&config, &bad_root, bad_checked.iter(), &STRATEGY),
            Err(Error::InvalidData)
        ));

        // Surplus shards are omitted from interpolation but remain bound by the root.
        let mut bad_surplus = honest;
        bad_surplus[total - 1][0] ^= 1;
        let (bad_root, bad_shards) = prove_codeword(bad_surplus);
        let bad_checked = check_basic(&scheme, &config, &bad_root, &bad_shards);
        assert!(matches!(
            scheme.decode(&config, &bad_root, bad_checked.iter().skip(1), &STRATEGY),
            Err(Error::InvalidData)
        ));
        Ok(())
    }

    fn assert_hinted_decode<I: Impl, const C: usize>(
        scheme: &OcelotHintedX<I, CountingSha256, C>,
        config: &Config,
        commitment: &Summary,
        checking_data: &CheckingData<<Sha256 as Hasher>::Digest>,
        checked: &[CheckedShard<<Sha256 as Hasher>::Digest>],
        indices: &[usize],
        expected: &[u8],
    ) {
        HASH_COUNTS.set((0, 0));
        let decoded = scheme
            .decode(
                config,
                commitment,
                checking_data.clone(),
                indices.iter().map(|&index| &checked[index]),
                &STRATEGY,
            )
            .unwrap();
        assert_eq!(decoded, expected);
        let originals = usize::from(config.minimum_shards.get());
        let missing = originals - indices.iter().filter(|&&index| index < originals).count();
        let (hashes, shard_hashes) = HASH_COUNTS.get();
        assert_eq!(shard_hashes, missing);
        if missing == 0 {
            assert_eq!(hashes, 0);
        }
    }

    fn assert_recovered_checksums<I: Impl, const C: usize>(
        imp: I,
        checking_data: &CheckingData<<Sha256 as Hasher>::Digest>,
        checked: &[CheckedShard<<Sha256 as Hasher>::Digest>],
        original: usize,
        indices: &[usize],
    ) {
        let mut input = vec![None; checked.len()];
        for &index in indices {
            input[index] = Some(checked[index].shard.as_ref());
        }
        for (index, shard) in Decoder::new(imp)
            .decode(&input[..original], &input[original..], &STRATEGY)
            .unwrap()
        {
            let mut checksum = [0; C];
            imp.checksum_range(
                &shard,
                &checking_data.coefficients,
                0..shard.len(),
                &mut checksum,
            );
            assert_eq!(checksum.as_slice(), checking_data.encoded_checksum[index]);
        }
    }

    fn fuzz_hinted(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let (config, _, _) = config(u)?;
        let data = data(u)?;
        check_hinted::<_, CHECKSUMS>(Impl8::new(Portable), &config, &data, u)?;
        check_hinted::<_, { CHECKSUMS * 2 }>(Impl16::new(Portable), &config, &data, u)
    }

    fn check_hinted<I: Impl, const C: usize>(
        imp: I,
        config: &Config,
        data: &[u8],
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        let original = usize::from(config.minimum_shards.get());
        let total = original + usize::from(config.extra_shards.get());
        let scheme = OcelotHintedX::<I, CountingSha256, C>::new(imp);
        let namespace = b"scheme property";
        let (commitment, shards) = scheme.encode(namespace, config, data, &STRATEGY).unwrap();
        let owner = u.choose_index(total)?;
        let codec = CodecConfig {
            maximum_shard_size: shards[owner].weak.shard.len(),
        };
        let owner_shard = StrongShard::decode_cfg(shards[owner].encode(), &codec).unwrap();
        let (checking_data, _, _) = scheme
            .weaken(
                namespace,
                config,
                &commitment,
                owner as u16,
                owner_shard,
                &STRATEGY,
            )
            .unwrap();
        let checked: Vec<_> = shards
            .iter()
            .enumerate()
            .map(|(index, shard)| {
                scheme
                    .check(
                        config,
                        &commitment,
                        &checking_data,
                        index as u16,
                        shard.weak.clone(),
                        &STRATEGY,
                    )
                    .unwrap()
            })
            .collect();

        let random_count = u.int_in_range(original..=total)?;
        let random = shuffled_indices(u, total, random_count)?;
        let systematic: Vec<_> = (0..original).collect();
        let mixed: Vec<_> = (1..original).chain([original]).collect();
        let recovery_only: Vec<_> = (original..2 * original).collect();
        let all_reversed: Vec<_> = (0..total).rev().collect();
        for indices in [&systematic, &mixed, &recovery_only, &all_reversed, &random] {
            assert_hinted_decode(
                &scheme,
                config,
                &commitment,
                &checking_data,
                &checked,
                indices,
                data,
            );
        }
        for indices in [&mixed, &recovery_only, &random] {
            assert_recovered_checksums::<_, C>(imp, &checking_data, &checked, original, indices);
        }

        assert!(matches!(
            scheme.decode(
                config,
                &commitment,
                checking_data.clone(),
                checked.iter().take(original - 1),
                &STRATEGY
            ),
            Err(Error::InsufficientShards(_, _))
        ));
        assert!(matches!(
            scheme.decode(
                config,
                &commitment,
                checking_data.clone(),
                [&checked[0], &checked[0]].into_iter(),
                &STRATEGY
            ),
            Err(Error::DuplicateIndex(0))
        ));

        let target = u.choose_index(total)?;
        let mut corrupt = shards[target].weak.clone();
        let offset = u.choose_index(corrupt.shard.len())?;
        let mut bytes = corrupt.shard.to_vec();
        bytes[offset] ^= 1;
        corrupt.shard = bytes.into();
        assert!(matches!(
            scheme.check(
                config,
                &commitment,
                &checking_data,
                target as u16,
                corrupt,
                &STRATEGY
            ),
            Err(Error::InvalidWeakShard)
        ));

        let mut wrong_proof = shards[target].weak.clone();
        wrong_proof.proof.siblings[0] = Sha256::hash(&[b"corrupt proof".as_slice()]);
        assert!(matches!(
            scheme.check(
                config,
                &commitment,
                &checking_data,
                target as u16,
                wrong_proof,
                &STRATEGY
            ),
            Err(Error::InvalidWeakShard)
        ));
        assert!(matches!(
            scheme.check(
                config,
                &commitment,
                &checking_data,
                total as u16,
                shards[target].weak.clone(),
                &STRATEGY
            ),
            Err(Error::InvalidIndex(_))
        ));
        let mut wrong_index = shards[target].weak.clone();
        wrong_index.index = ((target + 1) % total) as u16;
        assert!(matches!(
            scheme.check(
                config,
                &commitment,
                &checking_data,
                target as u16,
                wrong_index,
                &STRATEGY
            ),
            Err(Error::InvalidIndex(_))
        ));

        let mut short = shards[target].weak.clone();
        short.shard.truncate(short.shard.len() - 1);
        assert!(matches!(
            scheme.check(
                config,
                &commitment,
                &checking_data,
                target as u16,
                short,
                &STRATEGY
            ),
            Err(Error::InvalidWeakShard)
        ));
        let mut short_checksum = shards[owner].clone();
        short_checksum
            .checksum
            .truncate(short_checksum.checksum.len() - 1);
        assert!(matches!(
            scheme.weaken(
                namespace,
                config,
                &commitment,
                owner as u16,
                short_checksum,
                &STRATEGY
            ),
            Err(Error::InvalidStrongShard)
        ));
        assert!(matches!(
            scheme.weaken(
                b"other namespace",
                config,
                &commitment,
                owner as u16,
                shards[owner].clone(),
                &STRATEGY
            ),
            Err(Error::InvalidStrongShard)
        ));

        let other_commitment = scheme
            .encode(b"other namespace", config, data, &STRATEGY)
            .unwrap()
            .0;
        assert!(matches!(
            scheme.check(
                config,
                &other_commitment,
                &checking_data,
                target as u16,
                shards[target].weak.clone(),
                &STRATEGY
            ),
            Err(Error::CommitmentMismatch)
        ));

        let mut wrong_checked = checked[0].clone();
        wrong_checked.commitment = other_commitment;
        assert!(matches!(
            scheme.decode(
                config,
                &commitment,
                checking_data.clone(),
                [&wrong_checked]
                    .into_iter()
                    .chain(checked.iter().skip(1).take(original - 1)),
                &STRATEGY
            ),
            Err(Error::CommitmentMismatch)
        ));
        let mut wrong_checking_namespace = checking_data.clone();
        wrong_checking_namespace.namespace = b"other field";
        assert!(matches!(
            scheme.decode(
                config,
                &commitment,
                wrong_checking_namespace,
                checked.iter().take(original),
                &STRATEGY
            ),
            Err(Error::CommitmentMismatch)
        ));
        check_prefix_proof(&scheme, config, &commitment, &shards, data, u)?;
        check_checksum_collision(&scheme, config, &shards, data, &random, u)?;

        let mut wrong_checking_config = checking_data;
        wrong_checking_config.config = Config {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(1),
        };
        assert!(matches!(
            scheme.check(
                config,
                &commitment,
                &wrong_checking_config,
                target as u16,
                shards[target].weak.clone(),
                &STRATEGY
            ),
            Err(Error::CommitmentMismatch)
        ));
        Ok(())
    }

    thread_local! {
        static HASH_COUNTS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }

    #[derive(Default)]
    struct CountingSha256(Sha256);

    impl Hasher for CountingSha256 {
        type Digest = <Sha256 as Hasher>::Digest;

        fn hash(parts: &[&[u8]]) -> Self::Digest {
            let (hashes, shard_hashes) = HASH_COUNTS.get();
            // Bounded fuzz shards have one- or two-byte length prefixes, unlike
            // the four-byte BMT position/count prefixes and full digest pairs.
            let shard = parts.len() == 2 && parts[0].len() <= 2;
            HASH_COUNTS.set((hashes + 1, shard_hashes + usize::from(shard)));
            Sha256::hash(parts)
        }

        fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
            (Self::hash(left), Self::hash(right))
        }

        fn update(&mut self, bytes: &[u8]) -> &mut Self {
            self.0.update(bytes);
            self
        }

        fn finalize(self) -> (Self, Self::Digest) {
            let (hashes, shard_hashes) = HASH_COUNTS.get();
            HASH_COUNTS.set((hashes + 1, shard_hashes));
            let (hasher, digest) = self.0.finalize();
            (Self(hasher), digest)
        }
    }

    fn check_prefix_proof<I: Impl, const C: usize>(
        scheme: &OcelotHintedX<I, CountingSha256, C>,
        config: &Config,
        commitment: &Summary,
        shards: &[StrongShard<<Sha256 as Hasher>::Digest>],
        data: &[u8],
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        let original = usize::from(config.minimum_shards.get());
        let owner = &shards[u.choose_index(shards.len())?];
        let mut forged = owner.clone();
        let proof = &mut forged.original_proof;
        match u.int_in_range(0..=5)? {
            0 => {
                let index = u.choose_index(proof.siblings.len())?;
                proof.siblings[index] =
                    Sha256::hash(&[b"tampered prefix", proof.siblings[index].as_ref()]);
            }
            1 => {
                proof.siblings.pop();
            }
            2 => proof.siblings.push(owner.root),
            3 => {
                let mut builder = Builder::<Sha256>::new(shards.len());
                for shard in shards {
                    builder.add(&hash::shard::<Sha256>(&shard.weak.shard, &STRATEGY));
                }
                *proof = builder.build().range_proof(1, original as u32).unwrap();
            }
            4 => proof.leaf_count ^= u.int_in_range(1..=u32::MAX)?,
            _ => proof.siblings.resize(MAX_PREFIX_SIBLINGS + 1, owner.root),
        }
        let codec = CodecConfig {
            maximum_shard_size: owner.weak.shard.len(),
        };
        let decoded =
            StrongShard::<<Sha256 as Hasher>::Digest>::decode_cfg(forged.encode(), &codec);
        if forged.original_proof.siblings.len() > MAX_PREFIX_SIBLINGS {
            assert!(decoded.is_err());
        } else {
            assert_eq!(decoded.unwrap(), forged);
        }
        assert!(matches!(
            scheme.weaken(
                b"scheme property",
                config,
                commitment,
                owner.weak.index,
                forged.clone(),
                &STRATEGY,
            ),
            Err(Error::InvalidStrongShard)
        ));

        let transcript = |proof: &bmt::Proof<_>| {
            OcelotHintedX::<I, CountingSha256, C>::transcript(
                b"scheme property",
                config,
                owner.data_bytes,
                &owner.root,
                proof,
            )
        };
        let honest_coefficients = OcelotHintedX::<I, CountingSha256, C>::coefficients(
            &transcript(&owner.original_proof),
            owner.weak.shard.len(),
        )
        .unwrap();
        let mut transcript = transcript(&forged.original_proof);
        let coefficients = OcelotHintedX::<I, CountingSha256, C>::coefficients(
            &transcript,
            owner.weak.shard.len(),
        )
        .unwrap();
        assert_ne!(coefficients, honest_coefficients);
        let originals: Vec<_> = shards[..original]
            .iter()
            .map(|shard| shard.weak.shard.as_ref())
            .collect();
        forged.checksum = scheme
            .checksum(&originals, &coefficients, &STRATEGY)
            .unwrap();
        transcript.commit(forged.checksum.clone());
        let forged_commitment = transcript.summarize();
        assert_ne!(forged_commitment, *commitment);
        // Recommitting a malformed proof can pass weakening, but cannot authorize
        // a recovered payload. Already proven originals need no range verification.
        let invalid_shape = forged.original_proof.leaf_count != shards.len() as u32
            || forged.original_proof.siblings.len() > MAX_PREFIX_SIBLINGS;
        let result = scheme.weaken(
            b"scheme property",
            config,
            &forged_commitment,
            owner.weak.index,
            forged,
            &STRATEGY,
        );
        if invalid_shape {
            assert!(matches!(result, Err(Error::InvalidStrongShard)));
            return Ok(());
        }
        let (checking, _, _) = result.unwrap();
        let checked: Vec<_> = shards
            .iter()
            .enumerate()
            .map(|(index, shard)| {
                scheme
                    .check(
                        config,
                        &forged_commitment,
                        &checking,
                        index as u16,
                        shard.weak.clone(),
                        &STRATEGY,
                    )
                    .unwrap()
            })
            .collect();
        assert_hinted_decode(
            scheme,
            config,
            &forged_commitment,
            &checking,
            &checked,
            &(0..original).collect::<Vec<_>>(),
            data,
        );
        assert!(matches!(
            scheme.decode(
                config,
                &forged_commitment,
                checking,
                checked[original..2 * original].iter(),
                &STRATEGY
            ),
            Err(Error::InvalidData)
        ));
        Ok(())
    }

    fn check_checksum_collision<I: Impl, const C: usize>(
        scheme: &OcelotHintedX<I, CountingSha256, C>,
        config: &Config,
        shards: &[StrongShard<<Sha256 as Hasher>::Digest>],
        data: &[u8],
        random: &[usize],
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let original = usize::from(config.minimum_shards.get());
        let offset = u.choose_index(data.len())?;
        let mut other = data.to_vec();
        other[offset] ^= u.int_in_range(1..=u8::MAX)?;
        let (_, divergent) = scheme
            .encode(b"collision", config, other.as_slice(), &STRATEGY)
            .unwrap();
        let bytes: Vec<_> = shards[..original]
            .iter()
            .chain(&divergent[original..])
            .map(|shard| shard.weak.shard.clone())
            .collect();
        let mut builder = Builder::<Sha256>::new(bytes.len());
        for shard in &bytes {
            builder.add(&hash::shard::<Sha256>(shard, &STRATEGY));
        }
        let tree = builder.build();
        let weak: Vec<_> = bytes
            .into_iter()
            .enumerate()
            .map(|(index, shard)| WeakShard {
                shard,
                index: index as u16,
                proof: tree.proof(index as u32).unwrap(),
            })
            .collect();
        let strong = StrongShard {
            data_bytes: data.len() as u32,
            root: tree.root(),
            original_proof: tree.range_proof(0, original as u32 - 1).unwrap(),
            checksum: vec![0; original * C].into(),
            weak: weak[0].clone(),
        };
        let mut transcript = OcelotHintedX::<I, CountingSha256, C>::transcript(
            b"collision",
            config,
            strong.data_bytes,
            &strong.root,
            &strong.original_proof,
        );
        transcript.commit(strong.checksum.clone());
        let commitment = transcript.summarize();
        let mut checking = scheme
            .derive_checking_data(b"collision", config, &commitment, &strong, &STRATEGY)
            .unwrap();
        // Model a checksum collision without a cryptographic search. Every shard
        // still passes its production Merkle inclusion check against the same root.
        checking.coefficients = vec![0; checking.coefficients.len()].into();
        let checked: Vec<_> = weak
            .into_iter()
            .enumerate()
            .map(|(index, shard)| {
                scheme
                    .check(
                        config,
                        &commitment,
                        &checking,
                        index as u16,
                        shard,
                        &STRATEGY,
                    )
                    .unwrap()
            })
            .collect();
        assert_hinted_decode(
            scheme,
            config,
            &commitment,
            &checking,
            &checked,
            &(0..original).collect::<Vec<_>>(),
            data,
        );
        let changed_original = (u32::SIZE + offset) / checking.shard_len;
        let recovery_only: Vec<_> = (original..2 * original).collect();
        let mixed_surplus: Vec<_> = (0..checked.len())
            .rev()
            .filter(|&index| index != changed_original)
            .collect();
        for indices in [&recovery_only, &mixed_surplus] {
            let selection = select_shards::<I, _, _>(
                config,
                Some(checking.shard_len),
                indices.iter().map(|&i| &checked[i]),
                |shard| Ok((shard.index, shard.shard.as_ref(), shard.digest)),
            )
            .unwrap();
            let recovered =
                recover(scheme.imp, selection, RecoveryMode::Originals, &STRATEGY).unwrap();
            assert_eq!(
                extract_data::<I>(
                    &recovered.originals,
                    recovered.shard_len,
                    Some(checking.data_bytes)
                )
                .unwrap(),
                other
            );
            assert!(
                matches!(
                    scheme.decode(
                        config,
                        &commitment,
                        checking.clone(),
                        indices.iter().map(|&i| &checked[i]),
                        &STRATEGY
                    ),
                    Err(Error::InvalidData)
                ),
                "accepted a divergent payload after a checksum collision"
            );
        }
        match scheme.decode(
            config,
            &commitment,
            checking,
            random.iter().map(|&i| &checked[i]),
            &STRATEGY,
        ) {
            Ok(decoded) => assert_eq!(decoded, data),
            Err(Error::InvalidData) => {}
            Err(error) => panic!("unexpected decode error: {error}"),
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::ocelot::field::gf8::GF8;
        use commonware_invariants::minifuzz;
        use commonware_parallel::Rayon;
        use commonware_utils::{NZUsize, test_rng};

        const CONFIG: Config = Config {
            minimum_shards: NZU16!(3),
            extra_shards: NZU16!(4),
        };
        const FUZZ_CASES: u64 = 64;
        type Hinted = OcelotHintedX<Impl8<Portable>, Sha256, CHECKSUMS>;
        type Hinted16 = OcelotHintedX<Impl16<Portable>, Sha256, { CHECKSUMS * 2 }>;

        #[test]
        fn minifuzz_basic_roundtrip_and_rejection_properties() {
            minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(FUZZ_CASES)
                .test(|u| Plan::Basic.run(u));
        }

        #[test]
        fn minifuzz_hinted_roundtrip_and_rejection_properties() {
            minifuzz::Builder::default()
                .with_seed(0)
                .with_search_limit(FUZZ_CASES)
                .test(|u| Plan::Hinted.run(u));
        }

        #[test]
        fn topology_and_length_limits_are_rejected() {
            let max8 = Config {
                minimum_shards: NZU16!(128),
                extra_shards: NZU16!(128),
            };
            assert_eq!(topology::<Impl8<Portable>>(&max8).unwrap(), (128, 128, 256));
            assert!(matches!(
                topology::<Impl8<Portable>>(&Config {
                    minimum_shards: NZU16!(129),
                    extra_shards: NZU16!(128),
                }),
                Err(Error::InvalidShardCount)
            ));
            assert!(matches!(
                topology::<Impl8<Portable>>(&Config {
                    minimum_shards: NZU16!(1),
                    extra_shards: NZU16!(129),
                }),
                Err(Error::InvalidShardCount)
            ));

            let max16 = Config {
                minimum_shards: NZU16!(32768),
                extra_shards: NZU16!(32768),
            };
            assert_eq!(
                topology::<Impl16<Portable>>(&max16).unwrap(),
                (32768, 32768, 65536)
            );
            assert!(matches!(
                topology::<Impl16<Portable>>(&Config {
                    minimum_shards: NZU16!(32769),
                    ..max16
                }),
                Err(Error::InvalidShardCount)
            ));

            assert_eq!(
                coefficient_count::<Impl16<Portable>>(6).unwrap(),
                3 * CHECKSUMS
            );
            assert!(matches!(
                coefficient_count::<Impl16<Portable>>(5),
                Err(Error::InvalidData)
            ));
            assert!(matches!(
                coefficient_count::<Impl8<Portable>>(usize::MAX),
                Err(Error::InvalidData)
            ));
            assert!(matches!(
                shard_len::<Impl8<Portable>>(usize::MAX, 1),
                Err(Error::InvalidData)
            ));

            let scheme = Hinted::new(Impl8::new(Portable));
            let (commitment, mut shards) = scheme
                .encode(b"test", &CONFIG, &b"length"[..], &STRATEGY)
                .unwrap();
            shards[0].data_bytes = u32::MAX;
            assert!(matches!(
                scheme.weaken(
                    b"test",
                    &CONFIG,
                    &commitment,
                    0,
                    shards.remove(0),
                    &STRATEGY
                ),
                Err(Error::InvalidStrongShard)
            ));
        }

        #[test]
        fn hinted16_roundtrip_above_gf8_order() {
            let scheme = Hinted16::new(Impl16::new(Portable));
            let config = Config {
                minimum_shards: NZU16!(257),
                extra_shards: NZU16!(8),
            };
            let data: Vec<_> = (0..1027).map(|i| i as u8).collect();
            let (commitment, shards) = scheme
                .encode(b"test", &config, data.as_slice(), &STRATEGY)
                .unwrap();
            assert_eq!(shards[0].checksum.len(), 257 * CHECKSUMS * 2);
            let (checking_data, _, _) = scheme
                .weaken(
                    b"test",
                    &config,
                    &commitment,
                    0,
                    shards[0].clone(),
                    &STRATEGY,
                )
                .unwrap();
            let checked: Vec<_> = shards
                .iter()
                .enumerate()
                .skip(8)
                .map(|(index, shard)| {
                    scheme
                        .check(
                            &config,
                            &commitment,
                            &checking_data,
                            index as u16,
                            shard.weak.clone(),
                            &STRATEGY,
                        )
                        .unwrap()
                })
                .collect();
            assert_eq!(
                scheme
                    .decode(
                        &config,
                        &commitment,
                        checking_data,
                        checked.iter(),
                        &STRATEGY,
                    )
                    .unwrap(),
                data
            );
        }

        #[test]
        fn parallel_checksums_cross_stripe_boundaries() {
            let scheme = Hinted::new(Impl8::new(Portable));
            let len = stripe_bytes::<Impl8<Portable>>() + 65;
            let mut rng = test_rng();
            let mut shards = vec![vec![0; len]; 2];
            for shard in &mut shards {
                rng.fill_bytes(shard);
            }
            let mut coefficients = vec![0; CHECKSUMS * len];
            rng.fill_bytes(&mut coefficients);
            let shards: Vec<_> = shards.iter().map(Vec::as_slice).collect();
            let rayon = Rayon::new(NZUsize!(4)).unwrap().manual();
            let sequential = scheme.checksum(&shards, &coefficients, &STRATEGY).unwrap();
            let parallel = scheme.checksum(&shards, &coefficients, &rayon).unwrap();
            assert_eq!(parallel, sequential);

            for (shard, actual) in shards.iter().zip(parallel.as_chunks::<CHECKSUMS>().0) {
                for (output, &actual) in actual.iter().enumerate() {
                    let coefficients = &coefficients[output * len..(output + 1) * len];
                    let expected = shard.iter().zip(coefficients).fold(
                        GF8::from(0),
                        |sum, (&value, &coefficient)| {
                            sum + GF8::from(value) * GF8::from(coefficient)
                        },
                    );
                    assert_eq!(actual, u8::from(expected));
                }
            }
        }

        #[test]
        fn hinted_variants_are_domain_separated() {
            let ocelot8 = Hinted::new(Impl8::new(Portable));
            let ocelot16 = Hinted16::new(Impl16::new(Portable));
            let (commitment, shards) = ocelot8
                .encode(b"test", &CONFIG, &b"variant"[..], &STRATEGY)
                .unwrap();
            let (checking_data, checked, weak) = ocelot8
                .weaken(
                    b"test",
                    &CONFIG,
                    &commitment,
                    0,
                    shards[0].clone(),
                    &STRATEGY,
                )
                .unwrap();

            assert!(matches!(
                ocelot16.weaken(
                    b"test",
                    &CONFIG,
                    &commitment,
                    0,
                    shards[0].clone(),
                    &STRATEGY,
                ),
                Err(Error::InvalidStrongShard)
            ));
            assert!(matches!(
                ocelot16.check(&CONFIG, &commitment, &checking_data, 0, weak, &STRATEGY,),
                Err(Error::CommitmentMismatch)
            ));
            assert!(matches!(
                ocelot16.decode(
                    &CONFIG,
                    &commitment,
                    checking_data,
                    [&checked, &checked, &checked].into_iter(),
                    &STRATEGY,
                ),
                Err(Error::CommitmentMismatch)
            ));
        }

        #[test]
        fn basic_parallel_hashing_with_few_shards() {
            let scheme = Basic::new(Impl8::new(Portable));
            let config = Config {
                minimum_shards: NZU16!(1),
                extra_shards: NZU16!(2),
            };
            let data: Vec<_> = (0..2 * 1024 * 1024 + 1).map(|i| (i % 251) as u8).collect();
            let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
            let (expected, _) = scheme.encode(&config, data.as_slice(), &STRATEGY).unwrap();
            let (root, shards) = scheme.encode(&config, data.as_slice(), &strategy).unwrap();
            assert_eq!(root, expected);
            for index in [0, 2] {
                let checked = scheme
                    .check(&config, &root, index as u16, &shards[index], &strategy)
                    .unwrap();
                assert_eq!(
                    scheme
                        .decode(&config, &root, [&checked].into_iter(), &strategy)
                        .unwrap(),
                    data
                );
            }
        }

        #[test]
        fn hinted16_parallel_roundtrip_crosses_layout_and_stripe_boundaries() {
            let imp = Impl16::new(Portable);
            let scheme = Hinted16::new(imp);
            let shard_len = stripe_bytes::<Impl16<Portable>>() + 130;
            let mut data = vec![0; 3 * shard_len - u32::SIZE];
            test_rng().fill_bytes(&mut data);
            let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
            let (commitment, shards) = scheme
                .encode(b"test", &CONFIG, data.as_slice(), &strategy)
                .unwrap();
            let original_bytes: Vec<_> = shards[..3]
                .iter()
                .flat_map(|shard| shard.weak.shard.iter().copied())
                .collect();
            assert_eq!(
                &original_bytes[..u32::SIZE],
                &(data.len() as u32).to_be_bytes()
            );
            assert_eq!(&original_bytes[u32::SIZE..], data);

            let (checking_data, owner, _) = scheme
                .weaken(
                    b"test",
                    &CONFIG,
                    &commitment,
                    3,
                    shards[3].clone(),
                    &strategy,
                )
                .unwrap();
            for (index, shard) in shards.iter().enumerate() {
                let mut checksum = [0; CHECKSUMS * 2];
                imp.checksum_range(
                    &shard.weak.shard,
                    &checking_data.coefficients,
                    0..shard.weak.shard.len(),
                    &mut checksum,
                );
                assert_eq!(checksum.as_slice(), checking_data.encoded_checksum[index]);
            }
            let mut checked = vec![owner];
            for (index, shard) in shards.iter().enumerate().take(6).skip(4) {
                checked.push(
                    scheme
                        .check(
                            &CONFIG,
                            &commitment,
                            &checking_data,
                            index as u16,
                            shard.weak.clone(),
                            &strategy,
                        )
                        .unwrap(),
                );
            }
            assert_eq!(
                scheme
                    .decode(
                        &CONFIG,
                        &commitment,
                        checking_data,
                        checked.iter(),
                        &strategy,
                    )
                    .unwrap(),
                data
            );
        }

        #[test]
        fn hinted_rejects_committed_non_codeword() {
            let imp = Impl8::new(Portable);
            let scheme = Hinted::new(imp);
            let len = stripe_bytes::<Impl8<Portable>>() + 3;
            let data_bytes = (3 * len - u32::SIZE) as u32;
            let mut rng = test_rng();
            let mut originals = vec![vec![0; len]; 3];
            for shard in &mut originals {
                rng.fill_bytes(shard);
            }
            originals[0][..u32::SIZE].copy_from_slice(&data_bytes.to_be_bytes());
            let original_refs: Vec<_> = originals.iter().map(Vec::as_slice).collect();
            let mut recovery = Encoder::new(imp).encode(&original_refs, 4, &STRATEGY);
            recovery[0][len - 1] ^= 1;
            let shards: Vec<Bytes> = original_refs
                .iter()
                .map(|shard| Bytes::copy_from_slice(shard))
                .chain(recovery.into_iter().map(Bytes::from))
                .collect();
            let mut builder = Builder::<Sha256>::new(shards.len());
            for shard in &shards {
                builder.add(&hash::shard::<Sha256>(shard, &STRATEGY));
            }
            let tree = builder.build();
            let root = tree.root();
            let original_proof = tree.range_proof(0, 2).unwrap();
            let mut transcript =
                Hinted::transcript(b"test", &CONFIG, data_bytes, &root, &original_proof);
            let coefficients = Hinted::coefficients(&transcript, len).unwrap();
            let checksum = scheme
                .checksum(&original_refs, &coefficients, &STRATEGY)
                .unwrap();
            transcript.commit(checksum.clone());
            let commitment = transcript.summarize();
            let index = 3;
            let strong = StrongShard {
                data_bytes,
                root,
                original_proof,
                checksum,
                weak: WeakShard {
                    shard: shards[index].clone(),
                    index: index as u16,
                    proof: tree.proof(index as u32).unwrap(),
                },
            };

            assert!(matches!(
                scheme.weaken(
                    b"test",
                    &CONFIG,
                    &commitment,
                    index as u16,
                    strong,
                    &STRATEGY
                ),
                Err(Error::InvalidWeakShard)
            ));
        }

        fn raw_codeword(originals: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
            let refs: Vec<_> = originals.iter().map(Vec::as_slice).collect();
            let recovery = Encoder::new(Impl8::new(Portable)).encode(
                &refs,
                usize::from(CONFIG.extra_shards.get()),
                &STRATEGY,
            );
            originals.into_iter().chain(recovery).collect()
        }

        #[test]
        fn basic_rejects_noncanonical_length_padding_and_width() {
            let scheme = Basic::new(Impl8::new(Portable));
            let malformed = [
                // The declared payload does not fit in the original shards.
                [100u32.to_be_bytes().as_slice(), &[0, 0]].concat(),
                // One payload byte followed by non-zero padding at the canonical width.
                [1u32.to_be_bytes().as_slice(), &[9, 1]].concat(),
                // A valid one-byte payload padded to a non-canonical shard width.
                [1u32.to_be_bytes().as_slice(), &[9, 0, 0, 0, 0, 0, 0, 0]].concat(),
            ];
            for (flat, width) in malformed.into_iter().zip([2, 2, 4]) {
                let originals = flat.chunks_exact(width).map(<[u8]>::to_vec).collect();
                let (root, shards) = prove_codeword(raw_codeword(originals));
                let checked = check_basic(&scheme, &CONFIG, &root, &shards);
                assert!(matches!(
                    scheme.decode(&CONFIG, &root, checked[..3].iter(), &STRATEGY),
                    Err(Error::InvalidData)
                ));
            }
        }
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::{StrongShard, WeakShard};
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::sha256::Digest as Sha256Digest;

    commonware_conformance::conformance_tests! {
        CodecConformance<StrongShard<Sha256Digest>>,
        CodecConformance<WeakShard<Sha256Digest>>,
    }
}
