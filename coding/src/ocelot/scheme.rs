//! Coding schemes over generic shard arithmetic.

use super::code::{Decoder, Encoder, Impl, stripe_bytes};
use crate::{CodecConfig, Config};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{BufsMut, Encode, EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    Digest, Hasher,
    transcript::{Summary, Transcript, Version},
};
use commonware_parallel::Strategy;
use commonware_storage::bmt::{self, Builder};
use rand_core::Rng as _;
use std::marker::PhantomData;
use thiserror::Error;

/// Number of independent checksum outputs, each with 8 bits of soundness.
const CHECKSUMS: usize = 16;
/// At most 65,535 originals, each carrying 16 two-byte checksum symbols.
const MAX_CHECKSUM_BYTES: usize = CHECKSUMS * 2 * u16::MAX as usize;

fn coefficient_count(shard_len: usize, align: usize) -> Result<usize, Error> {
    if align == 0 || !shard_len.is_multiple_of(align) {
        return Err(Error::InvalidData);
    }
    (shard_len / align)
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
    /// Reconstructed framing, length, or padding is invalid.
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
    checksum: Bytes,
    weak: WeakShard<D>,
}

impl<D: Digest> Write for StrongShard<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.data_bytes.write(buf);
        self.root.write(buf);
        self.checksum.write(buf);
        self.weak.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.data_bytes.write(buf);
        self.root.write(buf);
        self.checksum.write_bufs(buf);
        self.weak.write_bufs(buf);
    }
}

impl<D: Digest> EncodeSize for StrongShard<D> {
    fn encode_size(&self) -> usize {
        self.data_bytes.encode_size()
            + self.root.encode_size()
            + self.checksum.encode_size()
            + self.weak.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.data_bytes.encode_inline_size()
            + self.root.encode_inline_size()
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
pub struct CheckedShard {
    commitment: Summary,
    index: u16,
    shard: Bytes,
}

/// A shard used by the basic scheme.
pub type Shard<D> = WeakShard<D>;

struct Encoding<D: Digest> {
    data_bytes: u32,
    shard_len: usize,
    originals: Bytes,
    root: D,
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
    if I::ALIGN == 0 {
        return Err(Error::InvalidShardCount);
    }
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
    mut data: impl Buf,
    strategy: &impl Strategy,
) -> Result<Encoding<H::Digest>, Error> {
    let (original_count, recovery_count, total) = topology::<I>(config)?;
    let data_len = data.remaining();
    let data_bytes = u32::try_from(data_len).map_err(|_| Error::DataTooLarge(data_len))?;
    let shard_len = shard_len::<I>(data_len, original_count)?;
    let padded_len = original_count
        .checked_mul(shard_len)
        .ok_or(Error::InvalidData)?;
    let mut padded = vec![0; padded_len];
    padded[..u32::SIZE].copy_from_slice(&data_bytes.to_be_bytes());
    data.copy_to_slice(&mut padded[u32::SIZE..u32::SIZE + data_len]);
    let originals = Bytes::from(padded);
    let original_refs: Vec<_> = originals.chunks_exact(shard_len).collect();
    let recovery = Encoder::new(imp).encode(&original_refs, recovery_count, strategy);
    let shard_bytes: Vec<Bytes> = (0..original_count)
        .map(|index| originals.slice(index * shard_len..(index + 1) * shard_len))
        .chain(recovery.into_iter().map(Bytes::from))
        .collect();

    let digests = strategy
        .map_collect_vec_with_multiplier(&shard_bytes, shard_len, |shard| H::hash(&[shard]));
    let mut builder = Builder::<H>::new(total);
    for digest in &digests {
        builder.add(digest);
    }
    let tree = builder.build();
    let root = tree.root();
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
) -> Result<H::Digest, Error> {
    let digest = H::hash(&[&shard.shard]);
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
) -> Result<H::Digest, Error> {
    validate_shard::<I, _>(config, index, shard, expected_shard_len)?;
    verify_shard_proof::<H>(root, index, shard)
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
    shard_len: usize,
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
    for (index, digest) in
        strategy.map_collect_vec_with_multiplier(missing, shard_len, |(index, shard)| {
            (index, H::hash(&[shard]))
        })
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

    fn topology(config: &Config) -> Result<(usize, usize, usize), Error> {
        topology::<I>(config)
    }

    #[allow(clippy::type_complexity)]
    pub fn encode(
        &self,
        config: &Config,
        data: impl Buf,
        strategy: &impl Strategy,
    ) -> Result<(H::Digest, Vec<Shard<H::Digest>>), Error> {
        let encoding = encode_codeword::<I, H>(self.imp, config, data, strategy)?;
        Ok((encoding.root, encoding.shards))
    }

    pub fn check(
        &self,
        config: &Config,
        commitment: &H::Digest,
        index: u16,
        shard: &Shard<H::Digest>,
        _strategy: &impl Strategy,
    ) -> Result<BasicCheckedShard<H::Digest>, Error> {
        let digest = verify_shard::<I, H>(config, commitment, index, shard, None)?;
        Ok(BasicCheckedShard {
            namespace: I::NAMESPACE,
            config: *config,
            commitment: *commitment,
            index,
            shard: shard.shard.clone(),
            digest,
        })
    }

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
        let canonical_recovery;
        let recovery: Vec<&[u8]> = if recovered.all_originals {
            canonical_recovery = Encoder::new(self.imp).encode(
                &originals,
                usize::from(config.extra_shards.get()),
                strategy,
            );
            for (provided, canonical) in recovered.recovery.iter().zip(&canonical_recovery) {
                if provided
                    .as_ref()
                    .is_some_and(|provided| provided.as_ref() != canonical)
                {
                    return Err(Error::InvalidData);
                }
            }
            canonical_recovery.iter().map(Vec::as_slice).collect()
        } else {
            recovered
                .recovery
                .iter()
                .map(|shard| shard.as_ref().map(AsRef::as_ref).ok_or(Error::InvalidData))
                .collect::<Result<_, _>>()?
        };
        verify_codeword::<H>(
            commitment,
            recovered.shard_len,
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

    fn topology(config: &Config) -> Result<(usize, usize, usize), Error> {
        topology::<I>(config)
    }

    fn shard_len(data_bytes: usize, original: usize) -> Result<usize, Error> {
        shard_len::<I>(data_bytes, original)
    }

    fn transcript(
        namespace: &[u8],
        config: &Config,
        data_bytes: u32,
        root: &H::Digest,
    ) -> Transcript {
        let mut transcript = Transcript::new(I::NAMESPACE, Version::V1);
        transcript.commit(namespace);
        transcript.commit(config.encode());
        transcript.commit(data_bytes.encode());
        transcript.commit(root.encode());
        transcript
    }

    fn coefficients(transcript: &Transcript, shard_len: usize) -> Result<Bytes, Error> {
        let len = coefficient_count(shard_len, I::ALIGN)?;
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
            || coefficients.len() != coefficient_count(shard_len, I::ALIGN)?
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

    fn reckon(
        &self,
        namespace: &[u8],
        config: &Config,
        commitment: &Summary,
        shard: &StrongShard<H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<CheckingData<H::Digest>, Error> {
        let (original, recovery, _) = Self::topology(config)?;
        let shard_len = Self::shard_len(shard.data_bytes as usize, original)?;
        let expected_checksum_len = original
            .checked_mul(CHECKSUM_BYTES)
            .ok_or(Error::InvalidStrongShard)?;
        if shard.weak.shard.len() != shard_len || shard.checksum.len() != expected_checksum_len {
            return Err(Error::InvalidStrongShard);
        }
        let mut transcript = Self::transcript(namespace, config, shard.data_bytes, &shard.root);
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
        weak: WeakShard<H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<CheckedShard, Error> {
        if checking_data.namespace != I::NAMESPACE || checking_data.commitment != *commitment {
            return Err(Error::CommitmentMismatch);
        }
        validate_shard::<I, _>(
            &checking_data.config,
            index,
            &weak,
            Some(checking_data.shard_len),
        )?;
        let checksum = self.checksum(&[&weak.shard], &checking_data.coefficients, strategy)?;
        if checksum != checking_data.encoded_checksum[usize::from(index)] {
            return Err(Error::InvalidWeakShard);
        }
        verify_shard_proof::<H>(&checking_data.root, index, &weak)?;
        Ok(CheckedShard {
            commitment: *commitment,
            index,
            shard: weak.shard,
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn encode(
        &self,
        namespace: &[u8],
        config: &Config,
        data: impl Buf,
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
        let mut transcript = Self::transcript(namespace, config, data_bytes, &root);
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
                checksum: checksum.clone(),
                weak,
            })
            .collect();
        Ok((commitment, strong))
    }

    #[allow(clippy::type_complexity)]
    pub fn weaken(
        &self,
        namespace: &[u8],
        config: &Config,
        commitment: &Summary,
        index: u16,
        shard: StrongShard<H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<(CheckingData<H::Digest>, CheckedShard, WeakShard<H::Digest>), Error> {
        let checking_data = self.reckon(namespace, config, commitment, &shard, strategy)?;
        let weak = shard.weak;
        let checked = self.check_weak(commitment, &checking_data, index, weak.clone(), strategy)?;
        Ok((checking_data, checked, weak))
    }

    pub fn check(
        &self,
        config: &Config,
        commitment: &Summary,
        checking_data: &CheckingData<H::Digest>,
        index: u16,
        weak: WeakShard<H::Digest>,
        strategy: &impl Strategy,
    ) -> Result<CheckedShard, Error> {
        if checking_data.config != *config {
            return Err(Error::InvalidWeakShard);
        }
        self.check_weak(commitment, checking_data, index, weak, strategy)
    }

    pub fn decode<'a>(
        &self,
        config: &Config,
        commitment: &Summary,
        checking_data: CheckingData<H::Digest>,
        shards: impl Iterator<Item = &'a CheckedShard>,
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
                Ok((shard.index, shard.shard.as_ref(), ()))
            })?;
        let recovered = recover(self.imp, selection, RecoveryMode::Originals, strategy)?;
        extract_data::<I>(
            &recovered.originals,
            recovered.shard_len,
            Some(checking_data.data_bytes),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OcelotHinted8 as Ocelot8, OcelotHinted16 as Ocelot16, PhasedScheme,
        ocelot::{
            Impl8,
            field::gf8::GF8,
            kernel::{Kernel, WithKernel, portable::Portable, with_kernel},
        },
    };
    use commonware_codec::Encode;
    use commonware_cryptography::Sha256;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{NZU16, NZUsize, test_rng};

    const CONFIG: Config = Config {
        minimum_shards: NZU16!(3),
        extra_shards: NZU16!(4),
    };

    #[test]
    fn ocelot16_roundtrip_above_256_shards() {
        let config = Config {
            minimum_shards: NZU16!(257),
            extra_shards: NZU16!(8),
        };
        let mut data = vec![0; 1027];
        test_rng().fill_bytes(&mut data);
        let (commitment, shards) =
            Ocelot16::<Sha256>::encode(b"test", &config, &data[..], &Sequential).unwrap();
        let cfg = CodecConfig {
            maximum_shard_size: 16,
        };
        let owner = StrongShard::read_cfg(&mut shards[0].encode(), &cfg).unwrap();
        assert_eq!(owner.checksum.len(), 257 * 32);
        let (checking_data, _, _) =
            Ocelot16::<Sha256>::weaken(b"test", &config, &commitment, 0, owner, &Sequential)
                .unwrap();
        let checked: Vec<_> = shards
            .iter()
            .enumerate()
            .skip(8)
            .map(|(index, shard)| {
                let weak = WeakShard::read_cfg(&mut shard.weak.encode(), &cfg).unwrap();
                Ocelot16::<Sha256>::check(
                    &config,
                    &commitment,
                    &checking_data,
                    index as u16,
                    weak,
                    &Sequential,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            Ocelot16::<Sha256>::decode(
                &config,
                &commitment,
                checking_data,
                checked.iter(),
                &Sequential,
            )
            .unwrap(),
            data,
        );
        assert!(matches!(
            Ocelot8::<Sha256>::encode(b"test", &config, &data[..], &Sequential),
            Err(Error::InvalidShardCount),
        ));
    }

    #[test]
    fn ocelot16_rejects_malformed_shards() {
        let (commitment, shards) =
            Ocelot16::<Sha256>::encode(b"test", &CONFIG, &b"odd length!"[..], &Sequential).unwrap();
        let (checking_data, _, _) = Ocelot16::<Sha256>::weaken(
            b"test",
            &CONFIG,
            &commitment,
            0,
            shards[0].clone(),
            &Sequential,
        )
        .unwrap();
        for byte in [0, shards[3].weak.shard.len() / 2] {
            let mut weak = shards[3].weak.clone();
            let mut corrupt = weak.shard.to_vec();
            corrupt[byte] ^= 1;
            weak.shard = corrupt.into();
            assert!(matches!(
                Ocelot16::<Sha256>::check(
                    &CONFIG,
                    &commitment,
                    &checking_data,
                    3,
                    weak,
                    &Sequential,
                ),
                Err(Error::InvalidWeakShard),
            ));
        }
        let mut weak = shards[3].weak.clone();
        weak.shard.truncate(weak.shard.len() - 1);
        assert!(matches!(
            Ocelot16::<Sha256>::check(&CONFIG, &commitment, &checking_data, 3, weak, &Sequential,),
            Err(Error::InvalidWeakShard),
        ));
        let mut strong = shards[0].clone();
        strong.checksum.truncate(strong.checksum.len() - 1);
        assert!(matches!(
            Ocelot16::<Sha256>::weaken(b"test", &CONFIG, &commitment, 0, strong, &Sequential,),
            Err(Error::InvalidStrongShard),
        ));
    }

    #[test]
    fn ocelot_variants_are_domain_separated() {
        let (commitment, shards) =
            Ocelot8::<Sha256>::encode(b"test", &CONFIG, &b"variant"[..], &Sequential).unwrap();
        let (checking_data, checked, weak) = Ocelot8::<Sha256>::weaken(
            b"test",
            &CONFIG,
            &commitment,
            0,
            shards[0].clone(),
            &Sequential,
        )
        .unwrap();
        assert!(matches!(
            Ocelot16::<Sha256>::weaken(
                b"test",
                &CONFIG,
                &commitment,
                0,
                shards[0].clone(),
                &Sequential,
            ),
            Err(Error::InvalidStrongShard),
        ));
        assert!(matches!(
            Ocelot16::<Sha256>::check(&CONFIG, &commitment, &checking_data, 0, weak, &Sequential,),
            Err(Error::CommitmentMismatch),
        ));
        let mut checked = vec![checked];
        for (index, shard) in shards.iter().enumerate().take(3).skip(1) {
            checked.push(
                Ocelot8::<Sha256>::check(
                    &CONFIG,
                    &commitment,
                    &checking_data,
                    index as u16,
                    shard.weak.clone(),
                    &Sequential,
                )
                .unwrap(),
            );
        }
        assert!(matches!(
            Ocelot16::<Sha256>::decode(
                &CONFIG,
                &commitment,
                checking_data,
                checked.iter(),
                &Sequential,
            ),
            Err(Error::CommitmentMismatch),
        ));
    }

    #[test]
    fn ocelot16_topology_limits() {
        type Scheme = OcelotHintedX<crate::ocelot::Impl16<Portable>, Sha256, 32>;
        let valid = Config {
            minimum_shards: NZU16!(32768),
            extra_shards: NZU16!(32768),
        };
        assert_eq!(Scheme::topology(&valid).unwrap(), (32768, 32768, 65536));
        let invalid = Config {
            minimum_shards: NZU16!(32769),
            ..valid
        };
        assert!(matches!(
            Scheme::topology(&invalid),
            Err(Error::InvalidShardCount)
        ));
        let padded_overflow = Config {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(32769),
        };
        assert!(matches!(
            Scheme::topology(&padded_overflow),
            Err(Error::InvalidShardCount)
        ));
    }

    #[test]
    fn ocelot16_preserves_bytes_across_layout_and_stripe_boundaries() {
        let len = stripe_bytes::<crate::ocelot::Impl16<Portable>>() + 130;
        let mut data = vec![0; 3 * len - u32::SIZE];
        test_rng().fill_bytes(&mut data);
        let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
        let (commitment, shards) =
            Ocelot16::<Sha256>::encode(b"test", &CONFIG, &data[..], &strategy).unwrap();
        let original_bytes: Vec<_> = shards[..3]
            .iter()
            .flat_map(|shard| shard.weak.shard.iter().copied())
            .collect();
        assert_eq!(
            &original_bytes[..u32::SIZE],
            &(data.len() as u32).to_be_bytes()
        );
        assert_eq!(&original_bytes[u32::SIZE..], data);

        let (checking_data, own_checked, _) = Ocelot16::<Sha256>::weaken(
            b"test",
            &CONFIG,
            &commitment,
            3,
            shards[3].clone(),
            &strategy,
        )
        .unwrap();
        let mut checked = vec![own_checked];
        for (index, shard) in shards.iter().enumerate().take(6).skip(4) {
            checked.push(
                Ocelot16::<Sha256>::check(
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
            Ocelot16::<Sha256>::decode(
                &CONFIG,
                &commitment,
                checking_data,
                checked.iter(),
                &strategy,
            )
            .unwrap(),
            data,
        );
    }

    #[test]
    fn roundtrip_from_recovery_shards() {
        let data = b"ocelot phased coding roundtrip";
        let (commitment, shards) =
            Ocelot8::<Sha256>::encode(b"test", &CONFIG, &data[..], &Sequential).unwrap();
        let read_cfg = CodecConfig {
            maximum_shard_size: 1024,
        };
        let owner = 3;
        let owner_shard = StrongShard::read_cfg(&mut shards[owner].encode(), &read_cfg).unwrap();
        let (checking_data, own_checked, _) = Ocelot8::<Sha256>::weaken(
            b"test",
            &CONFIG,
            &commitment,
            owner as u16,
            owner_shard,
            &Sequential,
        )
        .unwrap();
        let mut checked = vec![own_checked];
        for (index, shard) in shards.iter().enumerate().take(6).skip(4) {
            let (_, _, weak) = Ocelot8::<Sha256>::weaken(
                b"test",
                &CONFIG,
                &commitment,
                index as u16,
                shard.clone(),
                &Sequential,
            )
            .unwrap();
            let weak = WeakShard::read_cfg(&mut weak.encode(), &read_cfg).unwrap();
            checked.push(
                Ocelot8::<Sha256>::check(
                    &CONFIG,
                    &commitment,
                    &checking_data,
                    index as u16,
                    weak,
                    &Sequential,
                )
                .unwrap(),
            );
        }
        let decoded = Ocelot8::<Sha256>::decode(
            &CONFIG,
            &commitment,
            checking_data,
            checked.iter(),
            &Sequential,
        )
        .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn check_rejects_corrupt_shard() {
        let data = b"checksum rejection";
        let (commitment, shards) =
            Ocelot8::<Sha256>::encode(b"test", &CONFIG, &data[..], &Sequential).unwrap();
        let (checking_data, _, _) = Ocelot8::<Sha256>::weaken(
            b"test",
            &CONFIG,
            &commitment,
            0,
            shards[0].clone(),
            &Sequential,
        )
        .unwrap();
        let (_, _, mut weak) = Ocelot8::<Sha256>::weaken(
            b"test",
            &CONFIG,
            &commitment,
            3,
            shards[3].clone(),
            &Sequential,
        )
        .unwrap();
        let mut corrupt = weak.shard.to_vec();
        corrupt[0] ^= 1;
        weak.shard = corrupt.into();
        assert!(matches!(
            Ocelot8::<Sha256>::check(&CONFIG, &commitment, &checking_data, 3, weak, &Sequential),
            Err(Error::InvalidWeakShard)
        ));
    }

    struct TestChecksumRanges;

    impl WithKernel for TestChecksumRanges {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            let len = if cfg!(miri) {
                129
            } else {
                stripe_bytes::<Impl8<K>>() + 65
            };
            let mut rng = test_rng();
            let mut backing = vec![0; len + K::LANES];
            rng.fill_bytes(&mut backing);
            let offset = (K::LANES - backing.as_ptr() as usize % K::LANES) % K::LANES + 1;
            let shard = &backing[offset..offset + len];
            let mut coefficients = vec![0; CHECKSUMS * len];
            rng.fill_bytes(&mut coefficients);
            let ranges = [
                0..0,
                0..63,
                1..64,
                0..64,
                0..65,
                63..64,
                63..65,
                64..65,
                1..len,
                len - 65..len,
                0..len,
            ];
            for range in ranges {
                let mut portable = [255; CHECKSUMS];
                Impl8::new(Portable).checksum_range(
                    shard,
                    &coefficients,
                    range.clone(),
                    &mut portable,
                );
                let mut actual = [255; CHECKSUMS];
                Impl8::new(kernel).checksum_range(shard, &coefficients, range.clone(), &mut actual);
                assert_eq!(actual, portable);
                for (actual, coefficients) in
                    actual.iter().zip(coefficients.chunks_exact(shard.len()))
                {
                    let expected = shard[range.clone()]
                        .iter()
                        .zip(&coefficients[range.clone()])
                        .fold(GF8::from(0), |sum, (&value, &coefficient)| {
                            sum + GF8::from(value) * GF8::from(coefficient)
                        });
                    assert_eq!(*actual, u8::from(expected));
                }
            }

            let shards = [shard, shard];
            let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
            let portable = OcelotHintedX::<_, Sha256, CHECKSUMS>::new(Impl8::new(Portable))
                .checksum(&shards, &coefficients, &strategy)
                .unwrap();
            let dispatched = OcelotHintedX::<_, Sha256, CHECKSUMS>::new(Impl8::new(kernel))
                .checksum(&shards, &coefficients, &strategy)
                .unwrap();
            assert_eq!(dispatched, portable);
        }
    }

    #[test]
    fn checksum_ranges_match_scalar_inner_products() {
        with_kernel(TestChecksumRanges);
    }

    struct TestSchemeDifferential;

    impl WithKernel for TestSchemeDifferential {
        type Output = ();

        fn call<K: Kernel>(self, kernel: K) {
            let rayon = Rayon::new(NZUsize!(4)).unwrap().manual();
            assert_scheme_differential(kernel, &Sequential);
            assert_scheme_differential(kernel, &rayon);
        }
    }

    fn assert_scheme_differential<K: Kernel>(kernel: K, strategy: &impl Strategy) {
        let portable = OcelotHintedX::<_, Sha256, CHECKSUMS>::new(Impl8::new(Portable));
        let dispatched = OcelotHintedX::<_, Sha256, CHECKSUMS>::new(Impl8::new(kernel));
        let mut rng = test_rng();
        let mut data = vec![0; 1027];
        rng.fill_bytes(&mut data);
        let (portable_commitment, portable_shards) = portable
            .encode(b"scheme differential", &CONFIG, &data[..], strategy)
            .unwrap();
        let (dispatched_commitment, dispatched_shards) = dispatched
            .encode(b"scheme differential", &CONFIG, &data[..], strategy)
            .unwrap();
        assert_eq!(portable_commitment.encode(), dispatched_commitment.encode());
        assert_eq!(
            portable_shards
                .iter()
                .map(Encode::encode)
                .collect::<Vec<_>>(),
            dispatched_shards
                .iter()
                .map(Encode::encode)
                .collect::<Vec<_>>()
        );

        let (portable_checking, _, portable_weak) = portable
            .weaken(
                b"scheme differential",
                &CONFIG,
                &portable_commitment,
                0,
                dispatched_shards[0].clone(),
                strategy,
            )
            .unwrap();
        let (dispatched_checking, _, dispatched_weak) = dispatched
            .weaken(
                b"scheme differential",
                &CONFIG,
                &dispatched_commitment,
                0,
                portable_shards[0].clone(),
                strategy,
            )
            .unwrap();
        assert_eq!(portable_checking, dispatched_checking);
        assert_eq!(portable_weak.encode(), dispatched_weak.encode());

        let checked_by_portable: Vec<_> = dispatched_shards
            .iter()
            .enumerate()
            .map(|(index, shard)| {
                portable
                    .check(
                        &CONFIG,
                        &portable_commitment,
                        &dispatched_checking,
                        index as u16,
                        shard.weak.clone(),
                        strategy,
                    )
                    .unwrap()
            })
            .collect();
        let checked_by_dispatched: Vec<_> = portable_shards
            .iter()
            .enumerate()
            .map(|(index, shard)| {
                dispatched
                    .check(
                        &CONFIG,
                        &dispatched_commitment,
                        &portable_checking,
                        index as u16,
                        shard.weak.clone(),
                        strategy,
                    )
                    .unwrap()
            })
            .collect();
        for indices in [[0, 1, 2], [0, 3, 4]] {
            let portable_decoded = portable
                .decode(
                    &CONFIG,
                    &portable_commitment,
                    dispatched_checking.clone(),
                    indices.iter().map(|&index| &checked_by_dispatched[index]),
                    strategy,
                )
                .unwrap();
            let dispatched_decoded = dispatched
                .decode(
                    &CONFIG,
                    &dispatched_commitment,
                    portable_checking.clone(),
                    indices.iter().map(|&index| &checked_by_portable[index]),
                    strategy,
                )
                .unwrap();
            assert_eq!(portable_decoded, data);
            assert_eq!(dispatched_decoded, data);
        }
    }

    #[test]
    fn portable_and_dispatched_schemes_match() {
        with_kernel(TestSchemeDifferential);
    }

    #[test]
    fn tiled_checksums_match_scalar_inner_products() {
        let scheme = OcelotHintedX::<_, Sha256, CHECKSUMS>::new(Impl8::new(Portable));
        let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
        let mut rng = test_rng();
        for len in [0, 2 * stripe_bytes::<Impl8<Portable>>() + 3] {
            let mut shards = vec![vec![0; len]; 2];
            for shard in &mut shards {
                rng.fill_bytes(shard);
            }
            let mut coefficients = vec![0; CHECKSUMS * len];
            rng.fill_bytes(&mut coefficients);
            let shards: Vec<_> = shards.iter().map(Vec::as_slice).collect();
            let actual = scheme.checksum(&shards, &coefficients, &strategy).unwrap();
            for (shard, actual) in shards.iter().zip(actual.as_chunks::<CHECKSUMS>().0) {
                for (output, &actual) in actual.iter().enumerate() {
                    let expected = shard.iter().enumerate().fold(GF8::from(0), |sum, (i, &v)| {
                        sum + GF8::from(v) * GF8::from(coefficients[output * len + i])
                    });
                    assert_eq!(actual, u8::from(expected));
                }
            }
        }
        assert!(scheme.checksum(&[], &[], &strategy).unwrap().is_empty());
    }

    #[test]
    fn checksum_dimensions_are_per_code_symbol() {
        assert_eq!(coefficient_count(6, 2).unwrap(), 3 * CHECKSUMS);
        assert!(coefficient_count(5, 2).is_err());
    }

    #[test]
    fn checksum_rejects_merkle_committed_non_codeword() {
        let imp = Impl8::new(Portable);
        let scheme = OcelotHintedX::<_, Sha256, 16>::new(imp);
        let len = stripe_bytes::<Impl8<Portable>>() + 3;
        let data_bytes = (3 * len - u32::SIZE) as u32;
        let mut rng = test_rng();
        let mut originals = vec![vec![0; len]; 3];
        for shard in &mut originals {
            rng.fill_bytes(shard);
        }
        originals[0][..u32::SIZE].copy_from_slice(&data_bytes.to_be_bytes());
        let original_refs: Vec<_> = originals.iter().map(Vec::as_slice).collect();
        let mut recovery = Encoder::new(imp).encode(&original_refs, 4, &Sequential);
        recovery[0][len - 1] ^= 1;
        let shards: Vec<Bytes> = original_refs
            .iter()
            .map(|shard| Bytes::copy_from_slice(shard))
            .chain(recovery.into_iter().map(Bytes::from))
            .collect();
        let mut builder = Builder::<Sha256>::new(shards.len());
        for shard in &shards {
            builder.add(&Sha256::hash(&[shard]));
        }
        let tree = builder.build();
        let root = tree.root();
        let mut transcript = OcelotHintedX::<Impl8<Portable>, Sha256, 16>::transcript(
            b"test", &CONFIG, data_bytes, &root,
        );
        let coefficients =
            OcelotHintedX::<Impl8<Portable>, Sha256, 16>::coefficients(&transcript, len).unwrap();
        let checksum = scheme
            .checksum(&original_refs, &coefficients, &Sequential)
            .unwrap();
        transcript.commit(checksum.clone());
        let commitment = transcript.summarize();
        let index = 3;
        let strong = StrongShard {
            data_bytes,
            root,
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
                &Sequential
            ),
            Err(Error::InvalidWeakShard)
        ));
    }

    #[test]
    fn recovered_originals_match_committed_checksums() {
        let imp = Impl8::new(Portable);
        let scheme = OcelotHintedX::<_, Sha256, 16>::new(imp);
        let (commitment, shards) = scheme
            .encode(
                b"test",
                &CONFIG,
                &b"recovered checksum invariant"[..],
                &Sequential,
            )
            .unwrap();
        let (checking_data, _, _) = scheme
            .weaken(
                b"test",
                &CONFIG,
                &commitment,
                0,
                shards[0].clone(),
                &Sequential,
            )
            .unwrap();
        let checked: Vec<_> = shards
            .into_iter()
            .enumerate()
            .map(|(index, shard)| {
                scheme
                    .check(
                        &CONFIG,
                        &commitment,
                        &checking_data,
                        index as u16,
                        shard.weak,
                        &Sequential,
                    )
                    .unwrap()
            })
            .collect();
        let k = usize::from(CONFIG.minimum_shards.get());
        let decoder = Decoder::new(imp);
        // Every threshold subset, including mixed and recovery-only inputs.
        for mask in 0usize..1 << checked.len() {
            if mask.count_ones() as usize != k {
                continue;
            }
            let input: Vec<_> = checked
                .iter()
                .enumerate()
                .map(|(i, shard)| (mask & (1 << i) != 0).then_some(shard.shard.as_ref()))
                .collect();
            for (index, shard) in decoder
                .decode(&input[..k], &input[k..], &Sequential)
                .unwrap()
            {
                let mut checksum = [0; CHECKSUMS];
                imp.checksum_range(
                    &shard,
                    &checking_data.coefficients,
                    0..shard.len(),
                    &mut checksum,
                );
                assert_eq!(checksum.as_slice(), checking_data.encoded_checksum[index]);
            }
        }
    }

    #[test]
    fn decode_with_surplus_shards() {
        let data = b"only consume the shards needed for recovery";
        let (commitment, shards) =
            Ocelot8::<Sha256>::encode(b"test", &CONFIG, &data[..], &Sequential).unwrap();
        let (checking_data, _, _) = Ocelot8::<Sha256>::weaken(
            b"test",
            &CONFIG,
            &commitment,
            0,
            shards[0].clone(),
            &Sequential,
        )
        .unwrap();
        let checked: Vec<_> = shards
            .into_iter()
            .enumerate()
            .map(|(index, shard)| {
                Ocelot8::<Sha256>::check(
                    &CONFIG,
                    &commitment,
                    &checking_data,
                    index as u16,
                    shard.weak,
                    &Sequential,
                )
                .unwrap()
            })
            .collect();
        // Exercise systematic, mixed, and recovery-only inputs with surplus shards.
        for indices in [
            vec![0, 1, 2, 3, 4, 5, 6],
            vec![0, 3, 4, 5, 6],
            vec![3, 4, 5, 6],
        ] {
            let input = indices.iter().rev().map(|&i| &checked[i]);
            let decoded = Ocelot8::<Sha256>::decode(
                &CONFIG,
                &commitment,
                checking_data.clone(),
                input,
                &Sequential,
            );
            assert_eq!(decoded.unwrap(), data);
        }

        let mut wrong_commitment = checked[3].clone();
        wrong_commitment.commitment =
            Ocelot8::<Sha256>::encode(b"other", &CONFIG, &data[..], &Sequential)
                .unwrap()
                .0;
        assert!(matches!(
            Ocelot8::<Sha256>::decode(
                &CONFIG,
                &commitment,
                checking_data.clone(),
                checked[..3].iter().chain([&wrong_commitment]),
                &Sequential,
            ),
            Err(Error::CommitmentMismatch)
        ));
        assert!(matches!(
            Ocelot8::<Sha256>::decode(
                &CONFIG,
                &commitment,
                checking_data,
                checked.iter().chain([&checked[0]]),
                &Sequential,
            ),
            Err(Error::DuplicateIndex(0))
        ));
    }

    #[test]
    fn decode_rejects_duplicate_indices() {
        let (commitment, shards) =
            Ocelot8::<Sha256>::encode(b"test", &CONFIG, &b"duplicates"[..], &Sequential).unwrap();
        let (checking_data, checked, _) = Ocelot8::<Sha256>::weaken(
            b"test",
            &CONFIG,
            &commitment,
            0,
            shards[0].clone(),
            &Sequential,
        )
        .unwrap();
        assert!(matches!(
            Ocelot8::<Sha256>::decode(
                &CONFIG,
                &commitment,
                checking_data,
                [&checked, &checked, &checked].into_iter(),
                &Sequential,
            ),
            Err(Error::DuplicateIndex(0))
        ));
    }

    #[test]
    fn weaken_rejects_inconsistent_length_before_challenge_allocation() {
        let (commitment, mut shards) =
            Ocelot8::<Sha256>::encode(b"test", &CONFIG, &b"length"[..], &Sequential).unwrap();
        shards[0].data_bytes = u32::MAX;
        assert!(matches!(
            Ocelot8::<Sha256>::weaken(
                b"test",
                &CONFIG,
                &commitment,
                0,
                shards.remove(0),
                &Sequential
            ),
            Err(Error::InvalidStrongShard)
        ));
    }

    type Basic = super::OcelotX<Impl8<Portable>, Sha256>;

    fn prove_codeword(
        mut codeword: Vec<Vec<u8>>,
    ) -> (
        <Sha256 as Hasher>::Digest,
        Vec<WeakShard<<Sha256 as Hasher>::Digest>>,
    ) {
        let mut builder = Builder::<Sha256>::new(codeword.len());
        for shard in &codeword {
            builder.add(&Sha256::hash(&[shard]));
        }
        let tree = builder.build();
        let root = tree.root();
        let shards = codeword
            .drain(..)
            .enumerate()
            .map(|(index, shard)| WeakShard {
                shard: shard.into(),
                index: index as u16,
                proof: tree.proof(index as u32).unwrap(),
            })
            .collect();
        (root, shards)
    }

    fn raw_codeword(originals: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let refs: Vec<_> = originals.iter().map(Vec::as_slice).collect();
        let recovery = Encoder::new(Impl8::new(Portable)).encode(
            &refs,
            usize::from(CONFIG.extra_shards.get()),
            &Sequential,
        );
        originals.into_iter().chain(recovery).collect()
    }

    fn check_basic(
        scheme: &Basic,
        root: &<Sha256 as Hasher>::Digest,
        shards: &[WeakShard<<Sha256 as Hasher>::Digest>],
    ) -> Vec<BasicCheckedShard<<Sha256 as Hasher>::Digest>> {
        shards
            .iter()
            .enumerate()
            .map(|(index, shard)| {
                scheme
                    .check(&CONFIG, root, index as u16, shard, &Sequential)
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn basic_roundtrip_reconstructs_the_canonical_commitment() {
        let scheme = Basic::new(Impl8::new(Portable));
        let mut boundary = vec![0; 3 * (stripe_bytes::<Impl8<Portable>>() + 1) - u32::SIZE];
        test_rng().fill_bytes(&mut boundary);
        for data in [Vec::new(), vec![7], boundary] {
            let (root, shards) = scheme
                .encode(&CONFIG, data.as_slice(), &Sequential)
                .unwrap();
            let checked = check_basic(&scheme, &root, &shards);
            for indices in [[0, 1, 2], [0, 3, 4], [3, 4, 5]] {
                let decoded = scheme
                    .decode(
                        &CONFIG,
                        &root,
                        indices.iter().map(|&index| &checked[index]),
                        &Sequential,
                    )
                    .unwrap();
                assert_eq!(decoded, data);
                assert_eq!(
                    scheme
                        .encode(&CONFIG, decoded.as_slice(), &Sequential)
                        .unwrap()
                        .0,
                    root
                );
            }
        }
    }

    #[test]
    fn basic_rejects_non_codeword_roots_with_all_originals_or_surplus() {
        let scheme = Basic::new(Impl8::new(Portable));
        let (_, honest) = scheme
            .encode(&CONFIG, &b"committed non-codeword"[..], &Sequential)
            .unwrap();
        let honest: Vec<Vec<u8>> = honest.iter().map(|shard| shard.shard.to_vec()).collect();

        let mut bad_all_originals = honest.clone();
        bad_all_originals[3][0] ^= 1;
        let (root, shards) = prove_codeword(bad_all_originals);
        let checked = check_basic(&scheme, &root, &shards);
        assert!(matches!(
            scheme.decode(&CONFIG, &root, checked.iter(), &Sequential),
            Err(Error::InvalidData)
        ));

        let mut bad_surplus = honest;
        bad_surplus[6][0] ^= 1;
        let (root, shards) = prove_codeword(bad_surplus);
        let checked = check_basic(&scheme, &root, &shards);
        assert!(matches!(
            scheme.decode(
                &CONFIG,
                &root,
                [1, 2, 3, 4, 5, 6].into_iter().map(|index| &checked[index]),
                &Sequential,
            ),
            Err(Error::InvalidData)
        ));
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
            let checked = check_basic(&scheme, &root, &shards);
            assert!(matches!(
                scheme.decode(&CONFIG, &root, checked[..3].iter(), &Sequential),
                Err(Error::InvalidData)
            ));
        }
    }

    #[test]
    fn basic_checked_shards_bind_commitment_config_and_field() {
        let scheme = Basic::new(Impl8::new(Portable));
        let (root_a, shards_a) = scheme
            .encode(&CONFIG, &b"commitment a"[..], &Sequential)
            .unwrap();
        let (root_b, shards_b) = scheme
            .encode(&CONFIG, &b"commitment b"[..], &Sequential)
            .unwrap();
        let checked_a = check_basic(&scheme, &root_a, &shards_a);
        let checked_b = check_basic(&scheme, &root_b, &shards_b);
        assert!(matches!(
            scheme.decode(
                &CONFIG,
                &root_a,
                [&checked_a[0], &checked_a[1], &checked_b[2]].into_iter(),
                &Sequential,
            ),
            Err(Error::CommitmentMismatch)
        ));

        let other_config = Config {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(5),
        };
        assert!(matches!(
            scheme.decode(&other_config, &root_a, checked_a[..3].iter(), &Sequential,),
            Err(Error::CommitmentMismatch)
        ));

        let other_field = super::OcelotX::<crate::ocelot::Impl16<Portable>, Sha256>::new(
            crate::ocelot::Impl16::new(Portable),
        );
        assert!(matches!(
            other_field.decode(&CONFIG, &root_a, checked_a[..3].iter(), &Sequential),
            Err(Error::CommitmentMismatch)
        ));
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
