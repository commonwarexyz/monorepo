//! Types for erasure coding.

use crate::Block;
use commonware_codec::{Encode, EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_coding::{Config as CodingConfig, Scheme};
use commonware_cryptography::{Committable, Digest, Digestible, Hasher};
use commonware_utils::{Array, Span};
use rand_core::CryptoRngCore;
use std::ops::{Deref, Range};

const STRONG_SHARD_TAG: u8 = 0;
const WEAK_SHARD_TAG: u8 = 1;

/// A [Digest] containing a coding commitment and encoded [CodingConfig].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodingCommitment([u8; CodingCommitment::SIZE]);

impl CodingCommitment {
    /// Extracts the [CodingConfig] from this [CodingCommitment].
    pub fn config(&self) -> CodingConfig {
        let mut buf = &self.0[64..];
        CodingConfig::read(&mut buf).expect("CodingCommitment always contains a valid config")
    }

    /// Returns the block [Digest] from this [CodingCommitment].
    ///
    /// ## Panics
    ///
    /// Panics if the [Digest]'s [FixedSize::SIZE] is > 32 bytes.
    pub fn block_digest<D: Digest>(&self) -> D {
        self.take_digest(0..D::SIZE)
    }

    /// Returns the coding [Digest] from this [CodingCommitment].
    ///
    /// ## Panics
    ///
    /// Panics if the [Digest]'s [FixedSize::SIZE] is > 32 bytes.
    pub fn coding_digest<D: Digest>(&self) -> D {
        self.take_digest(32..32 + D::SIZE)
    }

    /// Extracts the [Digest] from this [CodingCommitment].
    ///
    /// ## Panics
    ///
    /// Panics if the [Digest]'s [FixedSize::SIZE] is > 32 bytes.
    fn take_digest<D: Digest>(&self, range: Range<usize>) -> D {
        const {
            assert!(
                D::SIZE <= 32,
                "Cannot extract Digest with size > 32 from CodingCommitment"
            );
        }

        D::read(&mut self.0[range].as_ref())
            .expect("CodingCommitment always contains a valid digest")
    }
}

impl Digest for CodingCommitment {
    fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut buf = [0u8; CodingCommitment::SIZE];
        rng.fill_bytes(&mut buf);
        Self(buf)
    }
}

impl Write for CodingCommitment {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_slice(&self.0);
    }
}

impl FixedSize for CodingCommitment {
    const SIZE: usize = 32 + 32 + CodingConfig::SIZE;
}

impl Read for CodingCommitment {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let mut arr = [0u8; CodingCommitment::SIZE];
        buf.copy_to_slice(&mut arr);
        Ok(CodingCommitment(arr))
    }
}

impl AsRef<[u8]> for CodingCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for CodingCommitment {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for CodingCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", commonware_utils::hex(self.as_ref()))
    }
}

impl std::fmt::Debug for CodingCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", commonware_utils::hex(self.as_ref()))
    }
}

impl Default for CodingCommitment {
    fn default() -> Self {
        Self([0u8; CodingCommitment::SIZE])
    }
}

impl<D: Digest> From<(D, D, CodingConfig)> for CodingCommitment {
    fn from((digest, commitment, config): (D, D, CodingConfig)) -> Self {
        const {
            assert!(
                D::SIZE <= 32,
                "Cannot create CodingCommitment from Digest with size > 32"
            );
        }

        let mut buf = [0u8; CodingCommitment::SIZE];
        buf[..D::SIZE].copy_from_slice(&digest);
        buf[32..32 + D::SIZE].copy_from_slice(&commitment);
        buf[64..].copy_from_slice(&config.encode());
        Self(buf)
    }
}

impl Span for CodingCommitment {}
impl Array for CodingCommitment {}

/// A shard of erasure coded data, either a strong shard (from the proposer) or a weak shard
/// (from a non-proposer).
///
/// A weak shard cannot be checked for validity on its own.
#[derive(Clone)]
pub enum DistributionShard<C: Scheme> {
    /// A shard that is broadcasted by the proposer, containing extra information for generating
    /// checking data.
    Strong(C::Shard),
    /// A shard that is broadcasted by a non-proposer, containing only the shard data.
    Weak(C::ReShard),
}

impl<C: Scheme> Write for DistributionShard<C> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            DistributionShard::Strong(shard) => {
                buf.put_u8(STRONG_SHARD_TAG);
                shard.write(buf);
            }
            DistributionShard::Weak(reshard) => {
                buf.put_u8(WEAK_SHARD_TAG);
                reshard.write(buf);
            }
        }
    }
}

impl<C: Scheme> EncodeSize for DistributionShard<C> {
    fn encode_size(&self) -> usize {
        1 + match self {
            DistributionShard::Strong(shard) => shard.encode_size(),
            DistributionShard::Weak(reshard) => reshard.encode_size(),
        }
    }
}

impl<C: Scheme> Read for DistributionShard<C> {
    type Cfg = commonware_coding::CodecConfig;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        shard_cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        match buf.get_u8() {
            STRONG_SHARD_TAG => {
                let shard = C::Shard::read_cfg(buf, shard_cfg)?;
                Ok(DistributionShard::Strong(shard))
            }
            WEAK_SHARD_TAG => {
                let reshard = C::ReShard::read_cfg(buf, shard_cfg)?;
                Ok(DistributionShard::Weak(reshard))
            }
            _ => Err(commonware_codec::Error::Invalid(
                "DistributionShard",
                "invalid tag",
            )),
        }
    }
}

impl<C: Scheme> PartialEq for DistributionShard<C> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (DistributionShard::Strong(a), DistributionShard::Strong(b)) => a == b,
            (DistributionShard::Weak(a), DistributionShard::Weak(b)) => a == b,
            _ => false,
        }
    }
}

impl<C: Scheme> Eq for DistributionShard<C> {}

/// A broadcastable shard of erasure coded data, including the coding commitment and
/// the configuration used to code the data.
pub struct Shard<C: Scheme, H: Hasher> {
    /// The coding commitment
    commitment: CodingCommitment,
    /// The index of this shard within the commitment.
    index: usize,
    /// An individual shard within the commitment.
    inner: DistributionShard<C>,
    /// Phantom data for the hasher.
    _hasher: std::marker::PhantomData<H>,
}

impl<C: Scheme, H: Hasher> Shard<C, H> {
    pub fn new(commitment: CodingCommitment, index: usize, inner: DistributionShard<C>) -> Self {
        Self {
            commitment,
            index,
            inner,
            _hasher: std::marker::PhantomData,
        }
    }

    /// Returns the index of this shard within the commitment.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Takes the inner [Shard].
    pub fn into_inner(self) -> DistributionShard<C> {
        self.inner
    }

    /// Verifies that this shard is valid for the given commitment and index.
    ///
    /// NOTE: If the inner shard is a weak shard, this will always return false, as weak shards
    /// cannot be verified in isolation.
    pub fn verify(&self) -> bool {
        match &self.inner {
            DistributionShard::Strong(shard) => C::reshard(
                &self.commitment.config(),
                &self.commitment.coding_digest(),
                self.index as u16,
                shard.clone(),
            )
            .is_ok(),
            DistributionShard::Weak(_) => false,
        }
    }

    /// Returns the UUID of a shard with the given commitment and index.
    #[inline]
    pub fn uuid(commitment: CodingCommitment, index: usize) -> H::Digest {
        let mut buf = [0u8; CodingCommitment::SIZE + u32::SIZE];
        buf[..commitment.encode_size()].copy_from_slice(&commitment);
        buf[commitment.encode_size()..].copy_from_slice((index as u32).to_le_bytes().as_ref());
        H::hash(&buf)
    }
}

impl<C: Scheme, H: Hasher> Clone for Shard<C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            index: self.index,
            inner: self.inner.clone(),
            _hasher: std::marker::PhantomData,
        }
    }
}

impl<C: Scheme, H: Hasher> Deref for Shard<C, H> {
    type Target = DistributionShard<C>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<C: Scheme, H: Hasher> Committable for Shard<C, H> {
    type Commitment = CodingCommitment;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<C: Scheme, H: Hasher> Digestible for Shard<C, H> {
    type Digest = H::Digest;

    fn digest(&self) -> Self::Digest {
        Self::uuid(self.commitment, self.index)
    }
}

impl<C: Scheme, H: Hasher> Write for Shard<C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.index.write(buf);
        self.inner.write(buf);
    }
}

impl<C: Scheme, H: Hasher> EncodeSize for Shard<C, H> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.index.encode_size() + self.inner.encode_size()
    }
}

impl<C: Scheme, H: Hasher> Read for Shard<C, H> {
    type Cfg = commonware_coding::CodecConfig;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let commitment = CodingCommitment::read(buf)?;
        let index = usize::read_cfg(buf, &RangeCfg::from(0..=u16::MAX as usize))?;
        let inner = DistributionShard::read_cfg(buf, cfg)?;

        Ok(Self {
            commitment,
            index,
            inner,
            _hasher: std::marker::PhantomData,
        })
    }
}

impl<C: Scheme, H: Hasher> PartialEq for Shard<C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment
            && self.index == other.index
            && self.inner == other.inner
    }
}

impl<C: Scheme, H: Hasher> Eq for Shard<C, H> {}

/// An envelope type for an erasure coded [Block].
#[derive(Debug)]
pub struct CodedBlock<B: Block, C: Scheme> {
    /// The inner block type.
    inner: B,
    /// The erasure coding configuration.
    config: CodingConfig,
    /// The erasure coding commitment.
    commitment: C::Commitment,
    /// The coded shards.
    ///
    /// These shards are optional to enable lazy construction.
    shards: Option<Vec<C::Shard>>,
}

impl<B: Block, C: Scheme<Commitment = B::Digest>> CodedBlock<B, C> {
    /// Erasure codes the block.
    fn encode(inner: &B, config: CodingConfig) -> (C::Commitment, Vec<C::Shard>) {
        let mut buf = Vec::with_capacity(config.encode_size() + inner.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);

        C::encode(&config, buf.as_slice()).expect("must encode block successfully")
    }

    /// Create a new [CodedBlock] from a [Block] and a configuration.
    pub fn new(inner: B, config: CodingConfig) -> Self {
        let (commitment, shards) = Self::encode(&inner, config);
        Self {
            inner,
            config,
            commitment,
            shards: Some(shards),
        }
    }

    /// Create a new [CodedBlock] from a [Block] and trusted [CodingCommitment].
    pub fn new_trusted(inner: B, commitment: CodingCommitment) -> Self {
        Self {
            inner,
            config: commitment.config(),
            commitment: commitment.coding_digest(),
            shards: None,
        }
    }

    /// Returns the coding configuration for the data committed.
    pub fn config(&self) -> CodingConfig {
        self.config
    }

    /// Returns a refernce to the shards in this coded block.
    pub fn shards(&mut self) -> &[C::Shard] {
        match self.shards {
            Some(ref shards) => shards,
            None => {
                let (commitment, shards) = Self::encode(&self.inner, self.config);

                assert_eq!(
                    commitment, self.commitment,
                    "coded block constructed with trusted commitment does not match commitment"
                );

                self.shards = Some(shards);

                // SAFETY: We just set self.shards to Some, so unwrap_unchecked is safe here.
                unsafe { self.shards.as_ref().unwrap_unchecked() }
            }
        }
    }

    /// Returns a [Shard] at the given index, if the index is valid.
    pub fn shard<H: Hasher>(&self, index: usize) -> Option<Shard<C, H>> {
        Some(Shard::new(
            self.commitment(),
            index,
            DistributionShard::Strong(self.shards.as_ref()?.get(index)?.clone()),
        ))
    }

    /// Returns a reference to the inner [Block].
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Takes the inner [Block].
    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<B: Block + Clone, C: Scheme> Clone for CodedBlock<B, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config,
            commitment: self.commitment,
            shards: self.shards.clone(),
        }
    }
}

impl<B: Block, C: Scheme<Commitment = B::Digest>> Committable for CodedBlock<B, C> {
    type Commitment = CodingCommitment;

    fn commitment(&self) -> Self::Commitment {
        CodingCommitment::from((self.digest(), self.commitment, self.config))
    }
}

impl<B: Block, C: Scheme> Digestible for CodedBlock<B, C> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.inner.digest()
    }
}

impl<B: Block, C: Scheme> Write for CodedBlock<B, C> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.config.write(buf);
    }
}

impl<B: Block, C: Scheme> EncodeSize for CodedBlock<B, C> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.config.encode_size()
    }
}

impl<B: Block, C: Scheme> Read for CodedBlock<B, C> {
    type Cfg = <B as Read>::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let inner = B::read_cfg(buf, cfg)?;
        let config = CodingConfig::read(buf)?;

        let mut buf = Vec::with_capacity(config.encode_size() + inner.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);
        let (commitment, shards) = C::encode(&config, buf.as_slice()).map_err(|_| {
            commonware_codec::Error::Invalid("CodedBlock", "Failed to re-commit to block")
        })?;

        Ok(Self {
            inner,
            config,
            commitment,
            shards: Some(shards),
        })
    }
}

impl<B: Block, C: Scheme> Block for CodedBlock<B, C> {
    fn height(&self) -> u64 {
        self.inner.height()
    }

    fn parent(&self) -> Self::Digest {
        self.inner.parent()
    }
}

impl<B: Block + PartialEq, C: Scheme> PartialEq for CodedBlock<B, C> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
            && self.config == other.config
            && self.commitment == other.commitment
            && self.shards == other.shards
    }
}

impl<B: Block + Eq, C: Scheme> Eq for CodedBlock<B, C> {}

/// A block identifier, either by its digest or its consensus [CodingCommitment].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestOrCommitment<D: Digest> {
    Digest(D),
    Commitment(CodingCommitment),
}

impl<D: Digest> DigestOrCommitment<D> {
    /// Returns the inner [Digest] for this identifier.
    pub fn digest(&self) -> D {
        match self {
            Self::Digest(digest) => *digest,
            Self::Commitment(commitment) => commitment.block_digest(),
        }
    }
}

/// Compute the [CodingConfig] for a given number of participants.
///
/// Currently, this function assumes `3f + 1` participants to tolerate at max `f` faults.
///
/// The generated coding configuration facilitates any `f + 1` parts to reconstruct the data.
pub fn coding_config_for_participants(n_participants: u16) -> CodingConfig {
    assert!(
        n_participants >= 4,
        "Need at least 4 participants to maintain fault tolerance"
    );
    let max_faults = (n_participants - 1) / 3;
    CodingConfig {
        minimum_shards: max_faults + 1,
        extra_shards: n_participants - (max_faults + 1),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::Block as MockBlock;
    use commonware_codec::{Decode, Encode};
    use commonware_coding::{CodecConfig, ReedSolomon};
    use commonware_cryptography::Sha256;

    const MAX_SHARD_SIZE: CodecConfig = CodecConfig {
        maximum_shard_size: 1024 * 1024, // 1 MiB
    };

    type H = Sha256;
    type RS = ReedSolomon<H>;
    type RShard = Shard<RS, H>;
    type Block = MockBlock<<H as Hasher>::Digest>;

    #[test]
    fn test_distribution_shard_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"commonware shape rotator club";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: 1,
            extra_shards: 2,
        };

        let (_, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let strong_shard = DistributionShard::<RS>::Strong(raw_shard.clone());
        let encoded = strong_shard.encode();
        let decoded =
            DistributionShard::<RS>::decode_cfg(&mut encoded.as_ref(), &MAX_SHARD_SIZE).unwrap();
        assert!(strong_shard == decoded);

        let weak_shard = DistributionShard::<RS>::Weak(raw_shard.clone());
        let encoded = weak_shard.encode();
        let decoded =
            DistributionShard::<RS>::decode_cfg(&mut encoded.as_ref(), &MAX_SHARD_SIZE).unwrap();
        assert!(weak_shard == decoded);
    }

    #[test]
    fn test_shard_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"deadc0de";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: 1,
            extra_shards: 2,
        };

        let (commitment, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let commitment = CodingCommitment::from((Sha256::empty(), commitment, CONFIG));
        let shard = RShard::new(commitment, 0, DistributionShard::Strong(raw_shard.clone()));
        let encoded = shard.encode();
        let decoded = RShard::decode_cfg(&mut encoded.as_ref(), &MAX_SHARD_SIZE).unwrap();
        assert!(shard == decoded);

        let shard = RShard::new(commitment, 0, DistributionShard::Weak(raw_shard));
        let encoded = shard.encode();
        let decoded = RShard::decode_cfg(&mut encoded.as_ref(), &MAX_SHARD_SIZE).unwrap();
        assert!(shard == decoded);
    }

    #[test]
    fn test_coded_block_codec_roundtrip() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: 1,
            extra_shards: 2,
        };

        let block = Block::new::<Sha256>(Sha256::hash(b"parent"), 42, 1_234_567);
        let coded_block = CodedBlock::<Block, RS>::new(block, CONFIG);

        let encoded = coded_block.encode();
        let decoded = CodedBlock::<Block, RS>::decode_cfg(encoded.freeze(), &()).unwrap();

        assert!(coded_block == decoded);
    }
}
