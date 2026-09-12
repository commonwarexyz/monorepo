//! Shared coding scheme over generic shard arithmetic.

use super::code::{Decoder, Encoder, Impl, stripe_bytes};
use crate::{CodecConfig, Config};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Encode, EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
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
const MAX_CHECKSUM_BYTES: usize = CHECKSUMS * u8::MAX as usize;

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
}

impl<D: Digest> EncodeSize for StrongShard<D> {
    fn encode_size(&self) -> usize {
        self.data_bytes.encode_size()
            + self.root.encode_size()
            + self.checksum.encode_size()
            + self.weak.encode_size()
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
    commitment: Summary,
    config: Config,
    data_bytes: u32,
    root: D,
    coefficients: Bytes,
    encoded_checksum: Vec<Bytes>,
    shard_len: usize,
}

/// A shard whose Merkle proof and checksum projection have been checked.
#[derive(Clone, Debug)]
pub struct CheckedShard {
    commitment: Summary,
    index: u16,
    shard: Bytes,
}

/// Reed-Solomon coding using `I` for arithmetic and `H` for commitments.
///
/// `CHECKSUM_BYTES` must hold exactly [`CHECKSUMS`] symbols of `I`.
pub struct OcelotX<I: Impl, H, const CHECKSUM_BYTES: usize> {
    imp: I,
    _marker: PhantomData<H>,
}

impl<I: Impl, H: Hasher, const CHECKSUM_BYTES: usize> OcelotX<I, H, CHECKSUM_BYTES> {
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

    fn shard_len(data_bytes: usize, original: usize) -> Result<usize, Error> {
        let prefixed = data_bytes
            .checked_add(u32::SIZE)
            .ok_or(Error::InvalidData)?;
        let unaligned = prefixed.div_ceil(original);
        unaligned
            .checked_next_multiple_of(I::ALIGN)
            .ok_or(Error::InvalidData)
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
        if checking_data.commitment != *commitment {
            return Err(Error::CommitmentMismatch);
        }
        let (_, _, total) = Self::topology(&checking_data.config)?;
        if usize::from(index) >= total {
            return Err(Error::InvalidIndex(index));
        }
        if weak.index != index {
            return Err(Error::InvalidIndex(weak.index));
        }
        if weak.shard.len() != checking_data.shard_len || weak.proof.leaf_count != total as u32 {
            return Err(Error::InvalidWeakShard);
        }
        let checksum = self.checksum(&[&weak.shard], &checking_data.coefficients, strategy)?;
        if checksum != checking_data.encoded_checksum[usize::from(index)] {
            return Err(Error::InvalidWeakShard);
        }
        let digest = H::hash(&[&weak.shard]);
        weak.proof
            .verify_element_inclusion::<H>(&digest, u32::from(index), &checking_data.root)
            .map_err(|_| Error::InvalidWeakShard)?;
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
        mut data: impl Buf,
        strategy: &impl Strategy,
    ) -> Result<(Summary, Vec<StrongShard<H::Digest>>), Error> {
        let (original, recovery, total) = Self::topology(config)?;
        let data_len = data.remaining();
        let data_bytes = u32::try_from(data_len).map_err(|_| Error::DataTooLarge(data_len))?;
        let shard_len = Self::shard_len(data_len, original)?;
        let padded_len = original.checked_mul(shard_len).ok_or(Error::InvalidData)?;
        let mut padded = vec![0; padded_len];
        padded[..u32::SIZE].copy_from_slice(&data_bytes.to_be_bytes());
        data.copy_to_slice(&mut padded[u32::SIZE..u32::SIZE + data_len]);
        let padded = Bytes::from(padded);
        let originals: Vec<_> = padded.chunks_exact(shard_len).collect();
        let recovery = Encoder::new(self.imp).encode(&originals, recovery, strategy);
        let shards: Vec<Bytes> = (0..original)
            .map(|index| padded.slice(index * shard_len..(index + 1) * shard_len))
            .chain(recovery.into_iter().map(Bytes::from))
            .collect();

        let digests: Vec<_> = strategy.map_collect_vec(&shards, |shard| H::hash(&[shard]));
        let mut builder = Builder::<H>::new(total);
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();
        let root = tree.root();
        let mut transcript = Self::transcript(namespace, config, data_bytes, &root);
        let coefficients = Self::coefficients(&transcript, shard_len)?;
        let checksum = self.checksum(&originals, &coefficients, strategy)?;
        transcript.commit(checksum.clone());
        let commitment = transcript.summarize();

        let strong = shards
            .into_iter()
            .enumerate()
            .map(|(index, shard)| {
                let index = index as u16;
                let proof = tree
                    .proof(u32::from(index))
                    .map_err(Error::FailedToCreateInclusionProof)?;
                Ok::<_, Error>(StrongShard {
                    data_bytes,
                    root,
                    checksum: checksum.clone(),
                    weak: WeakShard {
                        shard,
                        index,
                        proof,
                    },
                })
            })
            .collect::<Result<_, _>>()?;
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
        if checking_data.commitment != *commitment || checking_data.config != *config {
            return Err(Error::CommitmentMismatch);
        }
        let (original_count, recovery_count, total) = Self::topology(config)?;
        let mut originals = vec![None; original_count];
        let mut recovery = vec![None; recovery_count];
        let mut present = 0;
        for shard in shards {
            if shard.commitment != *commitment {
                return Err(Error::CommitmentMismatch);
            }
            let index = usize::from(shard.index);
            if index >= total || shard.shard.len() != checking_data.shard_len {
                return Err(Error::InvalidWeakShard);
            }
            let slot = if index < original_count {
                &mut originals[index]
            } else {
                &mut recovery[index - original_count]
            };
            if slot.replace(shard.shard.as_ref()).is_some() {
                return Err(Error::DuplicateIndex(shard.index));
            }
            present += 1;
        }
        if present < original_count {
            return Err(Error::InsufficientShards(present, original_count));
        }

        // Checksums commute with coding, so recovering from checked shards
        // also recovers the committed original checksums. Rechecking the
        // recovered originals with the same coefficients is redundant.
        let recovered = if originals.iter().all(Option::is_some) {
            Vec::new()
        } else {
            Decoder::new(self.imp).decode(&originals, &recovery, strategy)?
        };
        let mut recovered = recovered.into_iter();
        let mut padded = Vec::with_capacity(original_count * checking_data.shard_len);
        for (index, shard) in originals.into_iter().enumerate() {
            match shard {
                Some(shard) => padded.extend_from_slice(shard),
                None => {
                    let (recovered_index, shard) = recovered.next().ok_or(Error::InvalidData)?;
                    if recovered_index != index {
                        return Err(Error::InvalidData);
                    }
                    padded.extend_from_slice(&shard);
                }
            }
        }
        if recovered.next().is_some() || padded.len() < u32::SIZE {
            return Err(Error::InvalidData);
        }
        let encoded_len = u32::from_be_bytes(
            padded[..u32::SIZE]
                .try_into()
                .expect("length prefix has fixed size"),
        );
        if encoded_len != checking_data.data_bytes {
            return Err(Error::InvalidData);
        }
        let data_end = u32::SIZE
            .checked_add(encoded_len as usize)
            .ok_or(Error::InvalidData)?;
        if data_end > padded.len()
            || Self::shard_len(encoded_len as usize, original_count)? != checking_data.shard_len
            || padded[data_end..].iter().any(|&byte| byte != 0)
        {
            return Err(Error::InvalidData);
        }
        padded.copy_within(u32::SIZE..data_end, 0);
        padded.truncate(encoded_len as usize);
        Ok(padded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Ocelot8, PhasedScheme,
        ocelot::{Impl8, field::gf8::GF8, kernel::portable::Portable},
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

    #[test]
    fn checksum_ranges_match_scalar_inner_products() {
        let mut rng = test_rng();
        let mut shard = [0; 35];
        rng.fill_bytes(&mut shard);
        let mut coefficients = vec![0; CHECKSUMS * shard.len()];
        rng.fill_bytes(&mut coefficients);
        for range in [0..0, 0..1, 1..20, 20..35, 35..35, 0..35] {
            let mut actual = [255; CHECKSUMS];
            Impl8::new(Portable).checksum_range(&shard, &coefficients, range.clone(), &mut actual);
            for (actual, coefficients) in actual.iter().zip(coefficients.chunks_exact(shard.len()))
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
    }

    #[test]
    fn tiled_checksums_match_scalar_inner_products() {
        let scheme = OcelotX::<_, Sha256, CHECKSUMS>::new(Impl8::new(Portable));
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
        let scheme = OcelotX::<_, Sha256, 16>::new(imp);
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
        let mut transcript =
            OcelotX::<Impl8<Portable>, Sha256, 16>::transcript(b"test", &CONFIG, data_bytes, &root);
        let coefficients =
            OcelotX::<Impl8<Portable>, Sha256, 16>::coefficients(&transcript, len).unwrap();
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
        let scheme = OcelotX::<_, Sha256, 16>::new(imp);
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
