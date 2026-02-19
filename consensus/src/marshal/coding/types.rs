//! Types for erasure coding.

use crate::{
    types::{coding::Commitment, Height},
    Block, CertifiableBlock, Heightable,
};
use commonware_codec::{EncodeSize, Read, ReadExt, Write};
use commonware_coding::{Config as CodingConfig, Scheme};
use commonware_cryptography::{Committable, Digestible, Hasher};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::{Faults, N3f1, NZU16};
use std::{marker::PhantomData, ops::Deref};

const STRONG_SHARD_TAG: u8 = 0;
const WEAK_SHARD_TAG: u8 = 1;

/// A shard of erasure coded data, either a strong shard (from the proposer) or a weak shard
/// (from a non-proposer).
///
/// A weak shard cannot be checked for validity on its own.
#[derive(Clone)]
pub enum DistributionShard<C: Scheme> {
    /// A shard that is broadcasted by the proposer, containing extra information for generating
    /// checking data.
    Strong(C::StrongShard),
    /// A shard that is broadcasted by a non-proposer, containing only the shard data.
    Weak(C::WeakShard),
}

impl<C: Scheme> Write for DistributionShard<C> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Strong(shard) => {
                buf.put_u8(STRONG_SHARD_TAG);
                shard.write(buf);
            }
            Self::Weak(weak_shard) => {
                buf.put_u8(WEAK_SHARD_TAG);
                weak_shard.write(buf);
            }
        }
    }
}

impl<C: Scheme> EncodeSize for DistributionShard<C> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Strong(shard) => shard.encode_size(),
            Self::Weak(weak_shard) => weak_shard.encode_size(),
        }
    }
}

impl<C: Scheme> Read for DistributionShard<C> {
    type Cfg = commonware_coding::CodecConfig;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        shard_cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        match u8::read(buf)? {
            STRONG_SHARD_TAG => {
                let shard = C::StrongShard::read_cfg(buf, shard_cfg)?;
                Ok(Self::Strong(shard))
            }
            WEAK_SHARD_TAG => {
                let weak_shard = C::WeakShard::read_cfg(buf, shard_cfg)?;
                Ok(Self::Weak(weak_shard))
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
            (Self::Strong(a), Self::Strong(b)) => a == b,
            (Self::Weak(a), Self::Weak(b)) => a == b,
            _ => false,
        }
    }
}

impl<C: Scheme> Eq for DistributionShard<C> {}

#[cfg(feature = "arbitrary")]
impl<C: Scheme> arbitrary::Arbitrary<'_> for DistributionShard<C>
where
    C::StrongShard: for<'a> arbitrary::Arbitrary<'a>,
    C::WeakShard: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary::<bool>()? {
            Ok(Self::Strong(u.arbitrary()?))
        } else {
            Ok(Self::Weak(u.arbitrary()?))
        }
    }
}

/// A broadcastable shard of erasure coded data, including the coding commitment and
/// the configuration used to code the data.
pub struct Shard<C: Scheme, H: Hasher> {
    /// The coding commitment
    pub(crate) commitment: Commitment,
    /// The index of this shard within the commitment.
    pub(crate) index: u16,
    /// An individual shard within the commitment.
    pub(crate) inner: DistributionShard<C>,
    /// Phantom data for the hasher.
    _hasher: PhantomData<H>,
}

impl<C: Scheme, H: Hasher> Shard<C, H> {
    pub const fn new(commitment: Commitment, index: u16, inner: DistributionShard<C>) -> Self {
        Self {
            commitment,
            index,
            inner,
            _hasher: PhantomData,
        }
    }

    /// Returns the index of this shard within the commitment.
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Returns the [`Commitment`] for this shard.
    pub const fn commitment(&self) -> Commitment {
        self.commitment
    }

    /// Returns true if the inner shard is strong.
    pub const fn is_strong(&self) -> bool {
        matches!(self.inner, DistributionShard::Strong(_))
    }

    /// Returns true if the inner shard is weak.
    pub const fn is_weak(&self) -> bool {
        matches!(self.inner, DistributionShard::Weak(_))
    }

    /// Takes the inner [`DistributionShard`].
    pub fn into_inner(self) -> DistributionShard<C> {
        self.inner
    }

    /// Verifies the shard and returns the weak shard for broadcasting if valid.
    ///
    /// Returns `Some(weak_shard)` if the shard is valid and can be rebroadcast,
    /// or `None` if the shard is invalid or already weak.
    pub fn verify_into_weak(self) -> Option<Self> {
        let DistributionShard::Strong(shard) = self.inner else {
            return None;
        };

        let weak_shard = C::weaken(
            &self.commitment.config(),
            &self.commitment.root(),
            self.index,
            shard,
        )
        .ok()
        .map(|(_, _, weak_shard)| weak_shard)?;

        Some(Self::new(
            self.commitment,
            self.index,
            DistributionShard::Weak(weak_shard),
        ))
    }
}

impl<C: Scheme, H: Hasher> Clone for Shard<C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            index: self.index,
            inner: self.inner.clone(),
            _hasher: PhantomData,
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
    type Commitment = Commitment;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
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
        let commitment = Commitment::read(buf)?;
        let index = u16::read(buf)?;
        let inner = DistributionShard::read_cfg(buf, cfg)?;

        Ok(Self {
            commitment,
            index,
            inner,
            _hasher: PhantomData,
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

#[cfg(feature = "arbitrary")]
impl<C: Scheme, H: Hasher> arbitrary::Arbitrary<'_> for Shard<C, H>
where
    DistributionShard<C>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            commitment: u.arbitrary()?,
            index: u.arbitrary()?,
            inner: u.arbitrary()?,
            _hasher: PhantomData,
        })
    }
}

/// An envelope type for an erasure coded [`Block`].
#[derive(Debug)]
pub struct CodedBlock<B: Block, C: Scheme, H: Hasher> {
    /// The inner block type.
    inner: B,
    /// The erasure coding configuration.
    config: CodingConfig,
    /// The erasure coding commitment.
    commitment: C::Commitment,
    /// The coded shards.
    ///
    /// These shards are optional to enable lazy construction. If the block is
    /// constructed with [`Self::new_trusted`], the shards are computed lazily
    /// via [`Self::shards`].
    shards: Option<Vec<C::StrongShard>>,
    /// Phantom data for the hasher.
    _hasher: PhantomData<H>,
}

impl<B: Block, C: Scheme, H: Hasher> CodedBlock<B, C, H> {
    /// Erasure codes the block.
    fn encode(
        inner: &B,
        config: CodingConfig,
        strategy: &impl Strategy,
    ) -> (C::Commitment, Vec<C::StrongShard>) {
        let mut buf = Vec::with_capacity(config.encode_size() + inner.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);

        C::encode(&config, buf.as_slice(), strategy).expect("must encode block successfully")
    }

    /// Create a new [`CodedBlock`] from a [`Block`] and a configuration.
    pub fn new(inner: B, config: CodingConfig, strategy: &impl Strategy) -> Self {
        let (commitment, shards) = Self::encode(&inner, config, strategy);
        Self {
            inner,
            config,
            commitment,
            shards: Some(shards),
            _hasher: PhantomData,
        }
    }

    /// Create a new [`CodedBlock`] from a [`Block`] and trusted [`Commitment`].
    pub fn new_trusted(inner: B, commitment: Commitment) -> Self {
        Self {
            inner,
            config: commitment.config(),
            commitment: commitment.root(),
            shards: None,
            _hasher: PhantomData,
        }
    }

    /// Returns the coding configuration for the data committed.
    pub const fn config(&self) -> CodingConfig {
        self.config
    }

    /// Returns a reference to the shards in this coded block.
    ///
    /// If the shards have not yet been generated, they will be created via [`Scheme::encode`].
    pub fn shards(&mut self, strategy: &impl Strategy) -> &[C::StrongShard] {
        match self.shards {
            Some(ref shards) => shards,
            None => {
                let (commitment, shards) = Self::encode(&self.inner, self.config, strategy);

                assert_eq!(
                    commitment, self.commitment,
                    "coded block constructed with trusted commitment does not match commitment"
                );

                self.shards = Some(shards);
                self.shards.as_ref().unwrap()
            }
        }
    }

    /// Returns a [`Shard`] at the given index, if the index is valid.
    pub fn shard(&self, index: u16) -> Option<Shard<C, H>>
    where
        B: CertifiableBlock,
    {
        Some(Shard::new(
            self.commitment(),
            index,
            DistributionShard::Strong(self.shards.as_ref()?.get(usize::from(index))?.clone()),
        ))
    }

    /// Returns a reference to the inner [`Block`].
    pub const fn inner(&self) -> &B {
        &self.inner
    }

    /// Takes the inner [`Block`].
    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> From<CodedBlock<B, C, H>>
    for StoredCodedBlock<B, C, H>
{
    fn from(block: CodedBlock<B, C, H>) -> Self {
        Self::new(block)
    }
}

impl<B: Block + Clone, C: Scheme, H: Hasher> Clone for CodedBlock<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config,
            commitment: self.commitment,
            shards: self.shards.clone(),
            _hasher: PhantomData,
        }
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> Committable for CodedBlock<B, C, H> {
    type Commitment = Commitment;

    fn commitment(&self) -> Self::Commitment {
        Commitment::from((
            self.digest(),
            self.commitment,
            hash_context::<H, _>(&self.inner.context()),
            self.config,
        ))
    }
}

impl<B: Block, C: Scheme, H: Hasher> Digestible for CodedBlock<B, C, H> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.inner.digest()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Write for CodedBlock<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.config.write(buf);
    }
}

impl<B: Block, C: Scheme, H: Hasher> EncodeSize for CodedBlock<B, C, H> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.config.encode_size()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Read for CodedBlock<B, C, H> {
    type Cfg = <B as Read>::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        block_cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let inner = B::read_cfg(buf, block_cfg)?;
        let config = CodingConfig::read(buf)?;

        let mut buf = Vec::with_capacity(inner.encode_size() + config.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);
        let (commitment, shards) =
            C::encode(&config, buf.as_slice(), &Sequential).map_err(|_| {
                commonware_codec::Error::Invalid("CodedBlock", "Failed to re-commit to block")
            })?;

        Ok(Self {
            inner,
            config,
            commitment,
            shards: Some(shards),
            _hasher: PhantomData,
        })
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> Block for CodedBlock<B, C, H> {
    fn parent(&self) -> Self::Digest {
        self.inner.parent()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Heightable for CodedBlock<B, C, H> {
    fn height(&self) -> Height {
        self.inner.height()
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> CertifiableBlock for CodedBlock<B, C, H> {
    type Context = B::Context;

    fn context(&self) -> Self::Context {
        self.inner.context()
    }
}

/// Hashes a consensus context for inclusion in a [`Commitment`].
pub fn hash_context<H: Hasher, C: EncodeSize + Write>(context: &C) -> H::Digest {
    let mut buf = Vec::with_capacity(context.encode_size());
    context.write(&mut buf);
    H::hash(&buf)
}

impl<B: Block + PartialEq, C: Scheme, H: Hasher> PartialEq for CodedBlock<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
            && self.config == other.config
            && self.commitment == other.commitment
            && self.shards == other.shards
    }
}

impl<B: Block + Eq, C: Scheme, H: Hasher> Eq for CodedBlock<B, C, H> {}

/// A [`CodedBlock`] paired with its [`Commitment`] for efficient storage and retrieval.
///
/// This type should be preferred for storing verified [`CodedBlock`]s on disk - it
/// should never be sent over the network. Use [`CodedBlock`] for network transmission,
/// as it re-encodes the block with [`Scheme::encode`] on deserialization to ensure integrity.
///
/// When reading from storage, we don't need to re-encode the block to compute
/// the commitment - we stored it alongside the block when we first verified it.
/// This avoids expensive erasure coding operations on the read path.
///
/// The [`Read`] implementation performs a light verification (block digest check)
/// to detect storage corruption, but does not re-encode the block.
pub struct StoredCodedBlock<B: Block, C: Scheme, H: Hasher> {
    inner: B,
    commitment: Commitment,
    _scheme: PhantomData<(C, H)>,
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> StoredCodedBlock<B, C, H> {
    /// Create a [`StoredCodedBlock`] from a verified [`CodedBlock`].
    ///
    /// The caller must ensure the [`CodedBlock`] has been properly verified
    /// (i.e., its commitment was computed or validated against a trusted source).
    pub fn new(block: CodedBlock<B, C, H>) -> Self {
        Self {
            commitment: block.commitment(),
            inner: block.inner,
            _scheme: PhantomData,
        }
    }

    /// Convert back to a [`CodedBlock`] using the trusted commitment.
    ///
    /// The returned [`CodedBlock`] will have `shards: None`, meaning shards
    /// will be lazily generated if needed via [`CodedBlock::shards`].
    pub fn into_coded_block(self) -> CodedBlock<B, C, H> {
        CodedBlock::new_trusted(self.inner, self.commitment)
    }

    /// Returns a reference to the inner block.
    pub const fn inner(&self) -> &B {
        &self.inner
    }
}

/// Converts a [`StoredCodedBlock`] back to a [`CodedBlock`].
impl<B: Block, C: Scheme, H: Hasher> From<StoredCodedBlock<B, C, H>> for CodedBlock<B, C, H> {
    fn from(stored: StoredCodedBlock<B, C, H>) -> Self {
        Self::new_trusted(stored.inner, stored.commitment)
    }
}

impl<B: Block + Clone, C: Scheme, H: Hasher> Clone for StoredCodedBlock<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            inner: self.inner.clone(),
            _scheme: PhantomData,
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> Committable for StoredCodedBlock<B, C, H> {
    type Commitment = Commitment;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Block, C: Scheme, H: Hasher> Digestible for StoredCodedBlock<B, C, H> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.inner.digest()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Write for StoredCodedBlock<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.commitment.write(buf);
    }
}

impl<B: Block, C: Scheme, H: Hasher> EncodeSize for StoredCodedBlock<B, C, H> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.commitment.encode_size()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Read for StoredCodedBlock<B, C, H> {
    // Note: No concurrency parameter needed since we don't re-encode!
    type Cfg = B::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        block_cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let inner = B::read_cfg(buf, block_cfg)?;
        let commitment = Commitment::read(buf)?;

        // Light verification to detect storage corruption
        if inner.digest() != commitment.block::<B::Digest>() {
            return Err(commonware_codec::Error::Invalid(
                "StoredCodedBlock",
                "storage corruption: block digest mismatch",
            ));
        }

        Ok(Self {
            commitment,
            inner,
            _scheme: PhantomData,
        })
    }
}

impl<B: Block, C: Scheme, H: Hasher> Block for StoredCodedBlock<B, C, H> {
    fn parent(&self) -> Self::Digest {
        self.inner.parent()
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> CertifiableBlock for StoredCodedBlock<B, C, H> {
    type Context = B::Context;

    fn context(&self) -> Self::Context {
        self.inner.context()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Heightable for StoredCodedBlock<B, C, H> {
    fn height(&self) -> Height {
        self.inner.height()
    }
}

impl<B: Block + PartialEq, C: Scheme, H: Hasher> PartialEq for StoredCodedBlock<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment && self.inner == other.inner
    }
}

impl<B: Block + Eq, C: Scheme, H: Hasher> Eq for StoredCodedBlock<B, C, H> {}

/// Compute the [`CodingConfig`] for a given number of participants.
///
/// Panics if `n_participants < 4`.
pub fn coding_config_for_participants(n_participants: u16) -> CodingConfig {
    let max_faults = N3f1::max_faults(n_participants);
    assert!(
        max_faults >= 1,
        "Need at least 4 participants to maintain fault tolerance"
    );
    let max_faults = u16::try_from(max_faults).expect("max_faults must fit in u16");
    let minimum_shards = NZU16!(max_faults + 1);
    CodingConfig {
        minimum_shards,
        extra_shards: NZU16!(n_participants - minimum_shards.get()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{marshal::mocks::block::Block as MockBlock, Block as _};
    use commonware_codec::{Decode, Encode};
    use commonware_coding::{CodecConfig, ReedSolomon};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Digest, Sha256};

    const MAX_SHARD_SIZE: CodecConfig = CodecConfig {
        maximum_shard_size: 1024 * 1024, // 1 MiB
    };

    type H = Sha256;
    type RS = ReedSolomon<H>;
    type RShard = Shard<RS, H>;
    type Block = MockBlock<<H as Hasher>::Digest, ()>;

    #[test]
    fn test_distribution_shard_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"commonware shape rotator club";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let (_, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA, &Sequential).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let strong_shard = DistributionShard::<RS>::Strong(raw_shard.clone());
        let encoded = strong_shard.encode();
        let decoded =
            DistributionShard::<RS>::decode_cfg(&mut encoded.as_ref(), &MAX_SHARD_SIZE).unwrap();
        assert!(strong_shard == decoded);

        let weak_shard = DistributionShard::<RS>::Weak(raw_shard);
        let encoded = weak_shard.encode();
        let decoded =
            DistributionShard::<RS>::decode_cfg(&mut encoded.as_ref(), &MAX_SHARD_SIZE).unwrap();
        assert!(weak_shard == decoded);
    }

    #[test]
    fn test_distribution_shard_decode_truncated_returns_error() {
        let decode = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut buf = &[][..];
            DistributionShard::<RS>::decode_cfg(&mut buf, &MAX_SHARD_SIZE)
        }));
        assert!(decode.is_ok(), "decode must not panic on truncated input");
        assert!(decode.unwrap().is_err());
    }

    #[test]
    fn test_coding_config_for_participants_valid_for_minimum_set() {
        let config = coding_config_for_participants(4);
        assert_eq!(config.minimum_shards.get(), 2);
        assert_eq!(config.extra_shards.get(), 2);
    }

    #[test]
    #[should_panic(expected = "Need at least 4 participants to maintain fault tolerance")]
    fn test_coding_config_for_participants_panics_for_small_sets() {
        let _ = coding_config_for_participants(3);
    }

    #[test]
    fn test_shard_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"deadc0de";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let (commitment, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA, &Sequential).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let commitment =
            Commitment::from((Sha256Digest::EMPTY, commitment, Sha256Digest::EMPTY, CONFIG));
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
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = Block::new::<Sha256>((), Sha256::hash(b"parent"), Height::new(42), 1_234_567);
        let coded_block = CodedBlock::<Block, RS, H>::new(block, CONFIG, &Sequential);

        let encoded = coded_block.encode();
        let decoded = CodedBlock::<Block, RS, H>::decode_cfg(encoded, &()).unwrap();

        assert!(coded_block == decoded);
    }

    #[test]
    fn test_stored_coded_block_codec_roundtrip() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = Block::new::<Sha256>((), Sha256::hash(b"parent"), Height::new(42), 1_234_567);
        let coded_block = CodedBlock::<Block, RS, H>::new(block, CONFIG, &Sequential);
        let stored = StoredCodedBlock::<Block, RS, H>::new(coded_block.clone());

        assert_eq!(stored.commitment(), coded_block.commitment());
        assert_eq!(stored.digest(), coded_block.digest());
        assert_eq!(stored.height(), coded_block.height());
        assert_eq!(stored.parent(), coded_block.parent());

        let encoded = stored.encode();
        let decoded = StoredCodedBlock::<Block, RS, H>::decode_cfg(encoded, &()).unwrap();

        assert!(stored == decoded);
        assert_eq!(decoded.commitment(), coded_block.commitment());
        assert_eq!(decoded.digest(), coded_block.digest());
    }

    #[test]
    fn test_stored_coded_block_into_coded_block() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = Block::new::<Sha256>((), Sha256::hash(b"parent"), Height::new(42), 1_234_567);
        let coded_block = CodedBlock::<Block, RS, H>::new(block, CONFIG, &Sequential);
        let original_commitment = coded_block.commitment();
        let original_digest = coded_block.digest();

        let stored = StoredCodedBlock::<Block, RS, H>::new(coded_block);
        let encoded = stored.encode();
        let decoded = StoredCodedBlock::<Block, RS, H>::decode_cfg(encoded, &()).unwrap();
        let restored = decoded.into_coded_block();

        assert_eq!(restored.commitment(), original_commitment);
        assert_eq!(restored.digest(), original_digest);
    }

    #[test]
    fn test_stored_coded_block_corruption_detection() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = Block::new::<Sha256>((), Sha256::hash(b"parent"), Height::new(42), 1_234_567);
        let coded_block = CodedBlock::<Block, RS, H>::new(block, CONFIG, &Sequential);
        let stored = StoredCodedBlock::<Block, RS, H>::new(coded_block);

        let mut encoded = stored.encode().to_vec();

        // Corrupt the commitment (located after the block bytes)
        let block_size = stored.inner().encode_size();
        encoded[block_size] ^= 0xFF;

        // Decoding should fail due to digest mismatch
        let result = StoredCodedBlock::<Block, RS, H>::decode_cfg(&mut encoded.as_slice(), &());
        assert!(result.is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<DistributionShard<ReedSolomon<Sha256>>>,
            CodecConformance<Shard<ReedSolomon<Sha256>, Sha256>>,
        }
    }
}
