//! Types for erasure coded [Block] broadcast and reconstruction.

use crate::Block;
use commonware_codec::{EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_coding::{Config as CodingConfig, Scheme};
use commonware_cryptography::{Committable, Digestible, Hasher};
use std::{fmt::Debug, ops::Deref};

const STRONG_SHARD_TAG: u8 = 0;
const WEAK_SHARD_TAG: u8 = 1;

/// A shard of erasure coded data, either a strong shard (from the proposer) or a weak shard
/// (from a non-proposer).
///
/// A weak shard cannot be checked for validity on its own.
pub enum DistributionShard<S: Scheme> {
    /// A shard that is broadcasted by the proposer, containing extra information for generating
    /// checking data.
    Strong(S::Shard),
    /// A shard that is broadcasted by a non-proposer, containing only the shard data.
    Weak(S::ReShard),
}

impl<S: Scheme> Clone for DistributionShard<S> {
    fn clone(&self) -> Self {
        match self {
            DistributionShard::Strong(shard) => DistributionShard::Strong(shard.clone()),
            DistributionShard::Weak(reshard) => DistributionShard::Weak(reshard.clone()),
        }
    }
}

impl<S: Scheme> Write for DistributionShard<S> {
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

impl<S: Scheme> EncodeSize for DistributionShard<S> {
    fn encode_size(&self) -> usize {
        1 + match self {
            DistributionShard::Strong(shard) => shard.encode_size(),
            DistributionShard::Weak(reshard) => reshard.encode_size(),
        }
    }
}

impl<S: Scheme> Read for DistributionShard<S> {
    type Cfg = (<S::Shard as Read>::Cfg, <S::ReShard as Read>::Cfg);

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        (shard_cfg, reshard_cfg): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        match buf.get_u8() {
            STRONG_SHARD_TAG => {
                let shard = S::Shard::read_cfg(buf, shard_cfg)?;
                Ok(DistributionShard::Strong(shard))
            }
            WEAK_SHARD_TAG => {
                let reshard = S::ReShard::read_cfg(buf, reshard_cfg)?;
                Ok(DistributionShard::Weak(reshard))
            }
            _ => Err(commonware_codec::Error::Invalid(
                "DistributionShard",
                "invalid tag",
            )),
        }
    }
}

impl<S: Scheme> PartialEq for DistributionShard<S> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (DistributionShard::Strong(a), DistributionShard::Strong(b)) => a == b,
            (DistributionShard::Weak(a), DistributionShard::Weak(b)) => a == b,
            _ => false,
        }
    }
}

impl<S: Scheme> Eq for DistributionShard<S> {}

/// A broadcastable shard of erasure coded data, including the coding commitment and
/// the configuration used to code the data.
pub struct Shard<S: Scheme, H: Hasher> {
    /// The coding commitment
    commitment: S::Commitment,
    /// The coding configuration for the data committed.
    config: CodingConfig,
    /// The index of this shard within the commitment.
    index: usize,
    /// An individual shard within the commitment.
    inner: DistributionShard<S>,
    /// Phantom data for the hasher.
    _hasher: std::marker::PhantomData<H>,
}

impl<S: Scheme, H: Hasher> Shard<S, H> {
    pub fn new(
        commitment: S::Commitment,
        config: CodingConfig,
        index: usize,
        inner: DistributionShard<S>,
    ) -> Self {
        Self {
            commitment,
            config,
            index,
            inner,
            _hasher: std::marker::PhantomData,
        }
    }

    /// Returns the coding configuration for the data committed.
    pub fn config(&self) -> CodingConfig {
        self.config
    }

    /// Returns the index of this shard within the commitment.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Takes the inner [Shard].
    pub fn into_inner(self) -> DistributionShard<S> {
        self.inner
    }

    /// Returns the UUID of a shard with the given commitment and index.
    pub fn uuid(commitment: S::Commitment, index: usize) -> H::Digest {
        let mut buf = vec![0u8; S::Commitment::SIZE + u32::SIZE];
        buf[..commitment.encode_size()].copy_from_slice(&commitment);
        buf[commitment.encode_size()..].copy_from_slice((index as u32).to_le_bytes().as_ref());
        H::hash(&buf)
    }
}

impl<S: Scheme, H: Hasher> Clone for Shard<S, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            config: self.config,
            index: self.index,
            inner: self.inner.clone(),
            _hasher: std::marker::PhantomData,
        }
    }
}

impl<S: Scheme, H: Hasher> Deref for Shard<S, H> {
    type Target = DistributionShard<S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S: Scheme, H: Hasher> Committable for Shard<S, H> {
    type Commitment = S::Commitment;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<S: Scheme, H: Hasher> Digestible for Shard<S, H> {
    type Digest = H::Digest;

    fn digest(&self) -> Self::Digest {
        Self::uuid(self.commitment, self.index)
    }
}

impl<S: Scheme, H: Hasher> Write for Shard<S, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.config.write(buf);
        self.index.write(buf);
        self.inner.write(buf);
    }
}

impl<S: Scheme, H: Hasher> EncodeSize for Shard<S, H> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size()
            + self.config.encode_size()
            + self.index.encode_size()
            + self.inner.encode_size()
    }
}

impl<S: Scheme, H: Hasher> Read for Shard<S, H> {
    type Cfg = (<S::Shard as Read>::Cfg, <S::ReShard as Read>::Cfg);

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let commitment = S::Commitment::read(buf)?;
        let config = CodingConfig::read(buf)?;
        let index = usize::read_cfg(buf, &RangeCfg::from(0..=usize::MAX))?;
        let inner = DistributionShard::read_cfg(buf, cfg)?;

        Ok(Self {
            commitment,
            config,
            index,
            inner,
            _hasher: std::marker::PhantomData,
        })
    }
}

impl<S: Scheme, H: Hasher> PartialEq for Shard<S, H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment
            && self.config == other.config
            && self.index == other.index
            && self.inner == other.inner
    }
}

impl<S: Scheme, H: Hasher> Eq for Shard<S, H> {}

/// An envelope type for an erasure coded [Block].
#[derive(Debug)]
pub struct CodedBlock<B: Block, S: Scheme> {
    /// The inner block type.
    inner: B,
    /// The erasure coding configuration.
    config: CodingConfig,
    /// The erasure coding commitment.
    commitment: S::Commitment,
    /// The coded shards, along with corresponding coding proofs.
    shards: Vec<S::Shard>,
}

impl<B: Block, S: Scheme> CodedBlock<B, S> {
    /// Erasure codes the block.
    fn encode(inner: &B, config: CodingConfig) -> (S::Commitment, Vec<S::Shard>) {
        let mut buf = Vec::with_capacity(config.encode_size() + inner.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);

        S::encode(&config, buf.as_slice()).expect("encoding a block should not fail")
    }

    /// Create a new [CodedBlock] from a [Block] and a configuration.
    pub fn new(inner: B, config: CodingConfig) -> Self {
        let (commitment, chunks) = Self::encode(&inner, config);
        Self {
            inner,
            config,
            commitment,
            shards: chunks,
        }
    }

    /// Returns the coding configuration for the data committed.
    pub fn config(&self) -> CodingConfig {
        self.config
    }

    /// Returns a refernce to the shards in this coded block.
    pub fn shards(&self) -> &[S::Shard] {
        &self.shards
    }

    /// Returns a [Shard] at the given index, if the index is valid.
    pub fn shard<H: Hasher>(&self, index: usize) -> Option<Shard<S, H>> {
        Some(Shard::new(
            self.commitment,
            self.config,
            index,
            DistributionShard::Strong(self.shards.get(index)?.clone()),
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

impl<B: Block + Clone, S: Scheme> Clone for CodedBlock<B, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config,
            commitment: self.commitment,
            shards: self.shards.clone(),
        }
    }
}

impl<B: Block<Commitment = S::Commitment>, S: Scheme> Committable for CodedBlock<B, S> {
    type Commitment = B::Commitment;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Block, S: Scheme> Digestible for CodedBlock<B, S> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.inner.digest()
    }
}

impl<B: Block, S: Scheme> Write for CodedBlock<B, S> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.config.write(buf);
    }
}

impl<B: Block, S: Scheme> EncodeSize for CodedBlock<B, S> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.config.encode_size()
    }
}

impl<B: Block, S: Scheme> Read for CodedBlock<B, S> {
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
        let (commitment, shards) = S::encode(&config, buf.as_slice()).map_err(|_| {
            commonware_codec::Error::Invalid("CodedBlock", "Failed to re-commit to block")
        })?;

        Ok(Self {
            inner,
            config,
            commitment,
            shards,
        })
    }
}

impl<B: Block<Commitment = S::Commitment>, S: Scheme> Block for CodedBlock<B, S> {
    fn height(&self) -> u64 {
        self.inner.height()
    }

    fn parent(&self) -> Self::Commitment {
        self.inner.parent()
    }
}

impl<B, S> PartialEq for CodedBlock<B, S>
where
    B: Block + PartialEq,
    S: Scheme,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
            && self.config == other.config
            && self.commitment == other.commitment
            && self.shards == other.shards
    }
}

impl<B, S> Eq for CodedBlock<B, S>
where
    B: Block + Eq,
    S: Scheme,
{
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::Block as MockBlock;
    use commonware_codec::{Decode, Encode};
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::Sha256;

    const MAX_SHARD_SIZE: usize = 1024 * 1024; // 1 MiB

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
        let decoded = DistributionShard::<RS>::decode_cfg(
            &mut encoded.as_ref(),
            &(MAX_SHARD_SIZE, MAX_SHARD_SIZE),
        )
        .unwrap();
        assert!(strong_shard == decoded);

        let weak_shard = DistributionShard::<RS>::Weak(raw_shard.clone());
        let encoded = weak_shard.encode();
        let decoded = DistributionShard::<RS>::decode_cfg(
            &mut encoded.as_ref(),
            &(MAX_SHARD_SIZE, MAX_SHARD_SIZE),
        )
        .unwrap();
        assert!(weak_shard == decoded);
    }

    #[test]
    fn test_shard_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"commonware supremacy";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: 1,
            extra_shards: 2,
        };

        let (commitment, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let shard = RShard::new(
            commitment,
            CONFIG,
            0,
            DistributionShard::Strong(raw_shard.clone()),
        );
        let encoded = shard.encode();
        let decoded =
            RShard::decode_cfg(&mut encoded.as_ref(), &(MAX_SHARD_SIZE, MAX_SHARD_SIZE)).unwrap();
        assert!(shard == decoded);

        let shard = RShard::new(commitment, CONFIG, 0, DistributionShard::Weak(raw_shard));
        let encoded = shard.encode();
        let decoded =
            RShard::decode_cfg(&mut encoded.as_ref(), &(MAX_SHARD_SIZE, MAX_SHARD_SIZE)).unwrap();
        assert!(shard == decoded);
    }

    #[test]
    fn test_coded_block_codec_roundtrip() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: 1,
            extra_shards: 2,
        };

        let parent = Sha256::hash(b"parent");
        let block = Block::new::<Sha256>(parent, 42, 1_234_567);
        let coded_block = CodedBlock::<Block, RS>::new(block, CONFIG);

        let encoded = coded_block.encode();
        let decoded = CodedBlock::<Block, RS>::decode_cfg(encoded.freeze(), &()).unwrap();

        assert!(coded_block == decoded);
    }
}
