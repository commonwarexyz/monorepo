//! Types for erasure coding.

use crate::{
    Block, CertifiableBlock, Heightable,
    simplex::marshal::core::ExpectedCommitment,
    types::{Height, coding::Commitment},
};
use commonware_codec::{BufsMut, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_coding::{Config as CodingConfig, Scheme};
use commonware_cryptography::{Committable, Digested, Digestible, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{Faults, N3f1, NZU16};
use std::{
    future::Future,
    sync::{Arc, OnceLock},
};

/// A broadcastable shard of erasure coded data, including the coding commitment and
/// the configuration used to code the data.
pub struct Shard<B: Digestible, C: Scheme, H: Hasher> {
    /// The coding commitment
    pub(crate) commitment: Commitment<B, C, H>,
    /// The index of this shard within the commitment.
    pub(crate) index: u16,
    /// An individual shard within the commitment.
    pub(crate) inner: C::Shard,
}

impl<B: Digestible, C: Scheme, H: Hasher> Shard<B, C, H> {
    /// Returns the largest encoded size of a shard whose inner shard encodes to at most `shard`
    /// bytes.
    pub const fn max_encode_size(shard: usize) -> usize {
        shard + Commitment::<B, C, H>::SIZE + u16::SIZE
    }

    pub const fn new(commitment: Commitment<B, C, H>, index: u16, inner: C::Shard) -> Self {
        Self {
            commitment,
            index,
            inner,
        }
    }

    /// Returns the index of this shard within the commitment.
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Returns the [`Commitment`] for this shard.
    pub const fn commitment(&self) -> Commitment<B, C, H> {
        self.commitment
    }

    /// Takes the inner shard.
    pub fn into_inner(self) -> C::Shard {
        self.inner
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Clone for Shard<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            index: self.index,
            inner: self.inner.clone(),
        }
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Committable for Shard<B, C, H> {
    type Commitment = Commitment<B, C, H>;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Write for Shard<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.index.write(buf);
        self.inner.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.commitment.write(buf);
        self.index.write(buf);
        self.inner.write_bufs(buf);
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> EncodeSize for Shard<B, C, H> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.index.encode_size() + self.inner.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.commitment.encode_size() + self.index.encode_size() + self.inner.encode_inline_size()
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Read for Shard<B, C, H> {
    /// An upper bound on the encoded size of an application block.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl commonware_codec::Buf,
        max_block_size: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let commitment = Commitment::<B, C, H>::read(buf)?;
        let index = u16::read(buf)?;

        // A coded payload is the block followed by its coding config. The claimed config is
        // untrusted until consensus confirms the commitment, so the data width it admits may be
        // the scheme's widest for a payload at this bound.
        let maximum = max_block_size.saturating_add(CodingConfig::SIZE);
        let inner = C::Shard::read_cfg(buf, &(commitment.config(), maximum))?;

        Ok(Self {
            commitment,
            index,
            inner,
        })
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> PartialEq for Shard<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment
            && self.index == other.index
            && self.inner == other.inner
    }
}

impl<B: Digestible, C: Scheme, H: Hasher> Eq for Shard<B, C, H> {}

#[cfg(feature = "arbitrary")]
impl<B: Digestible, C: Scheme, H: Hasher> arbitrary::Arbitrary<'_> for Shard<B, C, H>
where
    Commitment<B, C, H>: for<'a> arbitrary::Arbitrary<'a>,
    C::Shard: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            commitment: u.arbitrary()?,
            index: u.arbitrary()?,
            inner: u.arbitrary()?,
        })
    }
}

/// An envelope type for an erasure coded [`Block`].
///
/// The consensus commitment is fixed when the block is built, decoded, or restored, so reading
/// the commitment or the inner block's digest never hashes or erasure codes.
#[derive(Debug)]
pub struct CodedBlock<B: Block, C: Scheme, H: Hasher> {
    /// The inner block type.
    inner: Arc<B>,
    /// The consensus commitment, binding the inner block's digest, the coding root, the digest
    /// of the consensus context, and the coding configuration.
    commitment: Commitment<B, C, H>,
    /// The coded shards.
    ///
    /// These shards are lazily-constructed when [`CodedBlock`] is formed without erasure coding,
    /// by [`Self::precomputed`], a trusted decode, or restoration from storage.
    shards: OnceLock<Arc<[C::Shard]>>,
}

impl<B: Block, C: Scheme, H: Hasher> CodedBlock<B, C, H> {
    /// Returns the largest encoded size of a coded block whose application block encodes to at
    /// most `application` bytes.
    pub const fn max_encode_size(application: usize) -> usize {
        application + CodingConfig::SIZE
    }

    /// Erasure codes the block.
    #[allow(clippy::type_complexity)]
    fn encode_shards(
        inner: &B,
        config: CodingConfig,
        strategy: &impl Strategy,
    ) -> Result<(C::Commitment, Vec<C::Shard>), C::Error> {
        let mut buf = Vec::with_capacity(inner.encode_size() + config.encode_size());
        inner.write(&mut buf);
        config.write(&mut buf);

        C::encode(&config, buf.as_slice(), strategy)
    }

    /// Creates a [`CodedBlock`] from a [`Block`] and its precomputed [`Commitment`].
    ///
    /// `commitment` must encode `inner`. [`Self::shards`] generates shards on
    /// demand and panics if the coding root does not match.
    ///
    /// Panics if `commitment` does not commit to the block's digest.
    pub fn precomputed(inner: Digested<B>, commitment: Commitment<B, C, H>) -> Self {
        assert_eq!(
            inner.digest(),
            commitment.block(),
            "commitment does not commit to block"
        );
        Self {
            inner: inner.into(),
            commitment,
            shards: OnceLock::new(),
        }
    }

    /// Returns the coding configuration for the data committed.
    pub fn config(&self) -> CodingConfig {
        self.commitment.config()
    }

    /// Returns a reference to the shards in this coded block.
    ///
    /// If the shards have not yet been generated, they will be created via [`Scheme::encode`].
    pub fn shards(&self, strategy: &impl Strategy) -> &[C::Shard] {
        self.shards.get_or_init(|| {
            let (root, shards) = Self::encode_shards(&self.inner, self.config(), strategy)
                .expect("must encode block successfully");

            // A mismatch means a commitment trusted at construction does not
            // encode this block, which is a contract violation or a consensus
            // safety failure. Never serve shards under a different root.
            assert_eq!(
                root,
                self.commitment.root(),
                "coded block constructed with trusted commitment does not match commitment"
            );

            shards.into()
        })
    }

    /// Returns a [`Shard`] at the given index, if the index is valid.
    pub fn shard(&self, index: u16) -> Option<Shard<B, C, H>> {
        Some(Shard::new(
            self.commitment,
            index,
            self.shards.get()?.get(usize::from(index))?.clone(),
        ))
    }

    /// Returns a reference to the inner [`Block`].
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Returns a shared reference to the inner [`Block`].
    pub fn inner_shared(&self) -> Arc<B> {
        Arc::clone(&self.inner)
    }

    /// Returns the inner [`Block`] with its digest, which the commitment binds.
    pub fn inner_digested(&self) -> Digested<B> {
        Digested::precomputed(Arc::clone(&self.inner), self.commitment.block())
    }
}

impl<B: CertifiableBlock, C: Scheme, H: Hasher> CodedBlock<B, C, H> {
    /// Builds the consensus commitment of `inner` from its coding `root` and `config`.
    fn commit(
        inner: &Digested<B>,
        root: C::Commitment,
        config: CodingConfig,
    ) -> Commitment<B, C, H> {
        Commitment::from((
            inner.digest(),
            root,
            hash_context::<H, _>(&inner.context()),
            config,
        ))
    }

    /// Erasure codes `inner` with `config` as a job on `strategy`, producing a [`CodedBlock`] that
    /// holds its shards.
    #[track_caller]
    pub fn encode(
        inner: Digested<B>,
        config: CodingConfig,
        strategy: &impl Strategy,
    ) -> impl Future<Output = Self> + Send + 'static {
        strategy.spawn(inner.encode_size(), move |strategy| {
            let (root, shards) = Self::encode_shards(inner.inner(), config, &strategy)
                .expect("must encode block successfully");
            Self {
                commitment: Self::commit(&inner, root, config),
                inner: inner.into(),
                shards: OnceLock::from(Arc::<[C::Shard]>::from(shards)),
            }
        })
    }

    /// Builds a [`CodedBlock`] from a decoded block and coding configuration, failing unless the
    /// result's commitment equals the one in `expected`.
    ///
    /// The block's digest and, for [`ExpectedCommitment::Untrusted`], its coding root are computed
    /// as jobs on `strategy`.
    pub(crate) fn from_decoded(
        inner: B,
        config: CodingConfig,
        expected: ExpectedCommitment<Commitment<B, C, H>>,
        strategy: &impl Strategy,
    ) -> impl Future<Output = Result<Self, commonware_codec::Error>> + Send {
        let (ExpectedCommitment::Trusted(commitment) | ExpectedCommitment::Untrusted(commitment)) =
            expected;
        let strategy = strategy.clone();
        async move {
            // Erasure coding is bounded by the expected config and skipped for a block that
            // cannot match, so both are checked before it.
            if config != commitment.config() {
                return Err(commonware_codec::Error::Invalid(
                    "CodedBlock",
                    "config mismatch",
                ));
            }
            let inner = Digested::compute(inner, &strategy).await;
            if inner.digest() != commitment.block() {
                return Err(commonware_codec::Error::Invalid(
                    "CodedBlock",
                    "block digest mismatch",
                ));
            }

            // A certified commitment already fixes the coding root of these bytes,
            // so recomputing it would only re-derive the root already in `expected`.
            let (root, shards) = match expected {
                ExpectedCommitment::Trusted(_) => (commitment.root(), None),
                ExpectedCommitment::Untrusted(_) => {
                    let encoding = inner.clone();
                    let (root, shards) = strategy
                        .spawn(inner.encode_size(), move |strategy| {
                            Self::encode_shards(encoding.inner(), config, &strategy)
                        })
                        .await
                        .map_err(|_| {
                            commonware_codec::Error::Invalid(
                                "CodedBlock",
                                "Failed to re-commit to block",
                            )
                        })?;
                    (root, Some(shards))
                }
            };

            // Binds the components not checked above, which are the root and the context digest.
            let computed = Self::commit(&inner, root, config);
            if computed != commitment {
                return Err(commonware_codec::Error::Invalid(
                    "CodedBlock",
                    "commitment mismatch",
                ));
            }
            Ok(Self {
                inner: inner.into(),
                commitment: computed,
                shards: shards.map_or_else(OnceLock::new, |shards| {
                    OnceLock::from(Arc::<[C::Shard]>::from(shards))
                }),
            })
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> From<CodedBlock<B, C, H>> for StoredCodedBlock<B, C, H> {
    fn from(block: CodedBlock<B, C, H>) -> Self {
        Self::new(block)
    }
}

/// Shares the inner block of a [`CodedBlock`] for archival.
impl<B: Block, C: Scheme, H: Hasher> From<Arc<CodedBlock<B, C, H>>> for StoredCodedBlock<B, C, H> {
    fn from(block: Arc<CodedBlock<B, C, H>>) -> Self {
        Self {
            commitment: block.commitment,
            inner: block.inner_shared(),
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> Clone for CodedBlock<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            commitment: self.commitment,
            shards: self.shards.clone(),
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> Committable for CodedBlock<B, C, H> {
    type Commitment = Commitment<B, C, H>;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Block, C: Scheme, H: Hasher> Digestible for CodedBlock<B, C, H> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.commitment.block()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Write for CodedBlock<B, C, H> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.config().write(buf);
    }
}

impl<B: Block, C: Scheme, H: Hasher> EncodeSize for CodedBlock<B, C, H> {
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.config().encode_size()
    }
}

impl<B: Block, C: Scheme, H: Hasher> Block for CodedBlock<B, C, H> {
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
    H::hash(&[&buf])
}

impl<B: Block + PartialEq, C: Scheme, H: Hasher> PartialEq for CodedBlock<B, C, H> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
            && self.commitment == other.commitment
            && self.shards == other.shards
    }
}

impl<B: Block + Eq, C: Scheme, H: Hasher> Eq for CodedBlock<B, C, H> {}

/// A [`CodedBlock`] paired with its [`Commitment`] for efficient storage and retrieval.
///
/// This type should be preferred for storing verified [`CodedBlock`]s on disk, and it
/// should never be sent over the network. Use [`CodedBlock`] for network transmission.
///
/// When reading from storage, we don't need to re-encode or hash the block to compute
/// the commitment, because we stored it alongside the block when we first verified it.
/// This avoids expensive erasure coding operations on the read path.
pub struct StoredCodedBlock<B: Block, C: Scheme, H: Hasher> {
    inner: Arc<B>,
    commitment: Commitment<B, C, H>,
}

impl<B: Block, C: Scheme, H: Hasher> StoredCodedBlock<B, C, H> {
    /// Create a [`StoredCodedBlock`] from a verified [`CodedBlock`].
    ///
    /// The caller must ensure the [`CodedBlock`] has been properly verified
    /// (i.e., its commitment was computed or validated against a trusted source).
    pub fn new(block: CodedBlock<B, C, H>) -> Self {
        Self {
            commitment: block.commitment,
            inner: block.inner,
        }
    }

    /// Convert back to a [`CodedBlock`] using the trusted commitment.
    ///
    /// The returned [`CodedBlock`] generates shards lazily if they are needed.
    pub fn into_coded_block(self) -> CodedBlock<B, C, H> {
        CodedBlock {
            inner: self.inner,
            commitment: self.commitment,
            shards: OnceLock::new(),
        }
    }

    /// Returns a reference to the inner block.
    pub fn inner(&self) -> &B {
        &self.inner
    }
}

/// Converts a [`StoredCodedBlock`] back to a [`CodedBlock`].
impl<B: Block, C: Scheme, H: Hasher> From<StoredCodedBlock<B, C, H>> for CodedBlock<B, C, H> {
    fn from(stored: StoredCodedBlock<B, C, H>) -> Self {
        stored.into_coded_block()
    }
}

/// Restores a shared [`CodedBlock`] from its stored form.
impl<B: Block, C: Scheme, H: Hasher> From<StoredCodedBlock<B, C, H>> for Arc<CodedBlock<B, C, H>> {
    fn from(stored: StoredCodedBlock<B, C, H>) -> Self {
        Self::new(stored.into())
    }
}

impl<B: Block, C: Scheme, H: Hasher> Clone for StoredCodedBlock<B, C, H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<B: Block, C: Scheme, H: Hasher> Committable for StoredCodedBlock<B, C, H> {
    type Commitment = Commitment<B, C, H>;

    fn commitment(&self) -> Self::Commitment {
        self.commitment
    }
}

impl<B: Block, C: Scheme, H: Hasher> Digestible for StoredCodedBlock<B, C, H> {
    type Digest = B::Digest;

    fn digest(&self) -> Self::Digest {
        self.commitment.block()
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

impl<B: Block + Read, C: Scheme, H: Hasher> Read for StoredCodedBlock<B, C, H> {
    type Cfg = B::Cfg;

    fn read_cfg(
        buf: &mut impl commonware_codec::Buf,
        block_cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let inner = B::read_cfg(buf, block_cfg)?;
        let commitment = Commitment::<B, C, H>::read(buf)?;
        Ok(Self {
            commitment,
            inner: Arc::new(inner),
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
    use crate::simplex::marshal::mocks::block::{EmptyBlock, encode_block};
    use bytes::Buf as _;
    use commonware_codec::{Decode, Encode, Error, Input};
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{Digest, Sha256, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::iobuf::EncodeExt;
    use futures::executor::block_on;

    const MAX_BLOCK_SIZE: usize = 1024 * 1024;

    type H = Sha256;
    type RS = ReedSolomon<H>;
    type TestBlock = EmptyBlock<H>;
    type RShard = Shard<TestBlock, RS, H>;

    /// Decodes a coded block's wire bytes against `expected` the way the coding variant does.
    fn decode(
        encoded: impl Input,
        expected: ExpectedCommitment<Commitment<TestBlock, RS, H>>,
    ) -> Result<CodedBlock<TestBlock, RS, H>, Error> {
        let (inner, config) = <(TestBlock, CodingConfig)>::decode_cfg(encoded, &((), ()))?;
        block_on(CodedBlock::from_decoded(
            inner,
            config,
            expected,
            &Sequential,
        ))
    }

    /// A shard decodes only when it is no wider than a block of the maximum size produces under
    /// the coding config its commitment claims.
    #[test]
    fn test_shard_width_bounded_by_commitment_config() {
        const MAX: usize = 1000;
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(2),
        };
        let encode = |len: usize, claimed: CodingConfig| {
            let (root, shards) =
                RS::encode(&CONFIG, vec![0u8; len].as_slice(), &Sequential).unwrap();
            let commitment =
                Commitment::from((Sha256Digest::EMPTY, root, Sha256Digest::EMPTY, claimed));
            RShard::new(commitment, 0, shards[0].clone()).encode()
        };

        // A maximum block and its coding config produce the widest admitted shard.
        let widest = MAX + CodingConfig::SIZE;
        assert!(RShard::decode_cfg(encode(widest, CONFIG), &MAX).is_ok());

        // One more byte widens the shard past the bound.
        assert!(RShard::decode_cfg(encode(widest + 1, CONFIG), &MAX).is_err());

        // A commitment claiming more minimum shards narrows the bound.
        let claimed = CodingConfig {
            minimum_shards: NZU16!(4),
            extra_shards: NZU16!(2),
        };
        assert!(RShard::decode_cfg(encode(widest, claimed), &MAX).is_err());
    }

    #[test]
    fn test_shard_wrapper_codec_roundtrip() {
        const MOCK_BLOCK_DATA: &[u8] = b"commonware shape rotator club";
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let (commitment, shards) = RS::encode(&CONFIG, MOCK_BLOCK_DATA, &Sequential).unwrap();
        let raw_shard = shards.first().cloned().unwrap();

        let commitment =
            Commitment::from((Sha256Digest::EMPTY, commitment, Sha256Digest::EMPTY, CONFIG));
        let shard = RShard::new(commitment, 0, raw_shard);
        let encoded = shard.encode();
        let decoded = RShard::decode_cfg(encoded, &MAX_BLOCK_SIZE).unwrap();
        assert!(shard == decoded);
    }

    #[test]
    fn test_shard_decode_truncated_returns_error() {
        let decode = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let buf = commonware_codec::Copying(&[]);
            RShard::decode_cfg(buf, &MAX_BLOCK_SIZE)
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
        let shard = RShard::new(commitment, 0, raw_shard);
        let encoded = shard.encode();
        let decoded = RShard::decode_cfg(encoded, &MAX_BLOCK_SIZE).unwrap();
        assert!(shard == decoded);
    }

    #[test]
    fn test_coded_block_codec_roundtrip() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = encode_block::<TestBlock, RS, H>(block, CONFIG);

        let encoded = coded_block.encode();
        let decoded = decode(
            encoded,
            ExpectedCommitment::Trusted(coded_block.commitment()),
        )
        .unwrap();
        assert_eq!(decoded.commitment(), coded_block.commitment());
        assert_eq!(decoded.shards(&Sequential), coded_block.shards(&Sequential));
        assert!(coded_block == decoded);

        // Binding the same bytes to an untrusted commitment recomputes the same block.
        let decoded = decode(
            coded_block.encode(),
            ExpectedCommitment::Untrusted(coded_block.commitment()),
        )
        .unwrap();
        assert!(coded_block == decoded);
    }

    #[test]
    fn test_coded_block_decode_rejects_config_mismatch() {
        const EXPECTED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(3),
        };
        const EMBEDDED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let expected =
            encode_block::<TestBlock, RS, H>(block.clone(), EXPECTED_CONFIG).commitment();
        let encoded = (block, EMBEDDED_CONFIG).encode();

        let Err(err) = decode(encoded, ExpectedCommitment::Untrusted(expected)) else {
            panic!("config mismatch should be rejected");
        };

        assert!(
            matches!(err, Error::Invalid("CodedBlock", "config mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_coded_block_decode_rejects_coding_root_mismatch() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        // Build an expected commitment that differs only in its coding root.
        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let commitment = coded.commitment();
        let wrong_root = Sha256::hash(&[b"wrong root"]);
        assert_ne!(wrong_root, commitment.root());
        let expected = Commitment::<TestBlock, RS, H>::from((
            commitment.block(),
            wrong_root,
            commitment.context(),
            commitment.config(),
        ));

        // Decoding must reject bytes that do not satisfy the exact expected
        // commitment.
        let Err(err) = decode(coded.encode(), ExpectedCommitment::Untrusted(expected)) else {
            panic!("coding root mismatch should be rejected");
        };

        assert!(
            matches!(err, Error::Invalid("CodedBlock", "commitment mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_coded_block_decode_trusted_is_lazy() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let decoded = decode(
            coded.encode(),
            ExpectedCommitment::Trusted(coded.commitment()),
        )
        .unwrap();

        // The root comes from the commitment and shards are generated on demand.
        assert_eq!(decoded.commitment(), coded.commitment());
        assert!(decoded.shard(0).is_none());
        assert_eq!(decoded.shards(&Sequential), coded.shards(&Sequential));
    }

    #[test]
    fn test_coded_block_decode_trusted_rejects_config_mismatch() {
        const EXPECTED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(3),
        };
        const EMBEDDED_CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let expected =
            encode_block::<TestBlock, RS, H>(block.clone(), EXPECTED_CONFIG).commitment();
        let encoded = (block, EMBEDDED_CONFIG).encode();

        let Err(err) = decode(encoded, ExpectedCommitment::Trusted(expected)) else {
            panic!("config mismatch should be rejected");
        };
        assert!(
            matches!(err, Error::Invalid("CodedBlock", "config mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn test_coded_block_decode_trusted_rejects_block_digest_mismatch() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let other = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(43), 1_234_567);
        let expected = encode_block::<TestBlock, RS, H>(block, CONFIG).commitment();
        assert_ne!(other.digest(), expected.block());
        let encoded = (other, CONFIG).encode();

        let Err(err) = decode(encoded, ExpectedCommitment::Trusted(expected)) else {
            panic!("block digest mismatch should be rejected");
        };

        assert!(
            matches!(err, Error::Invalid("CodedBlock", "block digest mismatch")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    #[should_panic(expected = "does not match commitment")]
    fn test_coded_block_trusted_wrong_root_panics_on_shards() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        // A trusted commitment is not re-encoded at decode, so a root that does
        // not encode the block is only caught when shards are generated.
        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let commitment = coded.commitment();
        let expected = Commitment::<TestBlock, RS, H>::from((
            commitment.block(),
            Sha256::hash(&[b"wrong root"]),
            commitment.context(),
            commitment.config(),
        ));
        let decoded = decode(coded.encode(), ExpectedCommitment::Trusted(expected)).unwrap();

        decoded.shards(&Sequential);
    }

    #[test]
    fn test_coded_block_clone_shares_shards() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let cloned = coded_block.clone();

        assert!(Arc::ptr_eq(&coded_block.inner, &cloned.inner));
        assert!(Arc::ptr_eq(
            coded_block.shards.get().unwrap(),
            cloned.shards.get().unwrap()
        ));
    }

    #[test]
    fn test_stored_coded_block_codec_roundtrip() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let stored = StoredCodedBlock::<TestBlock, RS, H>::new(coded_block.clone());

        assert_eq!(stored.commitment(), coded_block.commitment());
        assert_eq!(stored.digest(), coded_block.digest());
        assert_eq!(stored.height(), coded_block.height());
        assert_eq!(stored.parent(), coded_block.parent());

        let encoded = stored.encode();
        let decoded = StoredCodedBlock::<TestBlock, RS, H>::decode_cfg(encoded, &()).unwrap();

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

        let block = TestBlock::new(Sha256::hash(&[b"parent"]), Height::new(42), 1_234_567);
        let coded_block = encode_block::<TestBlock, RS, H>(block, CONFIG);
        let original_commitment = coded_block.commitment();
        let original_digest = coded_block.digest();

        let stored = StoredCodedBlock::<TestBlock, RS, H>::new(coded_block);
        let encoded = stored.encode();
        let decoded = StoredCodedBlock::<TestBlock, RS, H>::decode_cfg(encoded, &()).unwrap();
        let restored = decoded.into_coded_block();

        assert_eq!(restored.commitment(), original_commitment);
        assert_eq!(restored.digest(), original_digest);
    }

    #[test]
    fn test_shard_encode_iobufs_matches_encode() {
        const CONFIG: CodingConfig = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(2),
        };

        let (commitment, shards) =
            RS::encode(&CONFIG, b"iobufs encoding test".as_slice(), &Sequential).unwrap();
        let commitment =
            Commitment::from((Sha256Digest::EMPTY, commitment, Sha256Digest::EMPTY, CONFIG));
        let shard = RShard::new(commitment, 0, shards.into_iter().next().unwrap());

        let encoded = shard.encode();
        let mut encoded_iobufs = shard.encode_iobufs();
        let mut encoded_iobufs_bytes = vec![0u8; encoded_iobufs.remaining()];
        encoded_iobufs.copy_to_slice(&mut encoded_iobufs_bytes);
        assert_eq!(encoded_iobufs_bytes, encoded.as_ref());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Shard<TestBlock, ReedSolomon<Sha256>, Sha256>>,
        }
    }
}
