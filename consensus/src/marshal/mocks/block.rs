use crate::{
    marshal::coding::types::CodedBlock,
    simplex::types::Context,
    types::{Height, coding::Commitment},
};
use bytes::{BufMut, Bytes};
use commonware_codec::{
    Buf, Codec, Encode, EncodeSize, Error, FixedSize, MaxEncodeSize, Read, ReadExt, Write,
    varint::UInt,
};
use commonware_coding::{Config as CodingConfig, Scheme};
use commonware_cryptography::{Digest, Digested, Digestible, Hasher, PublicKey};
use commonware_parallel::Sequential;
#[cfg(test)]
use commonware_utils::sync::Mutex;
use futures::FutureExt as _;
use std::fmt::Debug;
#[cfg(test)]
use std::{
    collections::BTreeMap,
    sync::{
        Arc, LazyLock, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Computes a block's digest and wraps the block with its identity.
pub fn ready<B: crate::Block>(block: B) -> Digested<B> {
    let digest = block.digest();
    Digested::precomputed(block, digest)
}

/// Encodes a block with its digest and coding configuration using the sequential strategy.
pub fn encode_block<B: crate::CertifiableBlock, C: Scheme, H: Hasher>(
    block: B,
    config: CodingConfig,
) -> CodedBlock<B, C, H> {
    // The sequential strategy runs the job before returning its future, so one poll resolves
    // it. Blocking on a nested executor instead would panic in callers that already run inside
    // one, such as conformance tests.
    CodedBlock::encode(ready(block), config, &Sequential)
        .now_or_never()
        .expect("sequential encoding is ready on the first poll")
}

/// Per-test counters follow a block's encoded identity through archive decoding.
/// Tests must register distinct blocks and keep the counter alive while work is pending.
#[derive(Default)]
#[cfg(test)]
pub struct DigestCounter {
    calls: Arc<AtomicUsize>,
    digests: Vec<Vec<u8>>,
}

#[cfg(test)]
static DIGEST_COUNTERS: LazyLock<Mutex<BTreeMap<Vec<u8>, Weak<AtomicUsize>>>> =
    LazyLock::new(Mutex::default);

#[cfg(test)]
impl DigestCounter {
    /// Counts raw digest calls for this block and any decoded copies.
    pub fn track<D: Digest, C>(&mut self, block: &Block<D, C>) {
        let digest = block.digest.as_ref().to_vec();
        let previous = DIGEST_COUNTERS
            .lock()
            .insert(digest.clone(), Arc::downgrade(&self.calls));
        assert!(previous.and_then(|counter| counter.upgrade()).is_none());
        self.digests.push(digest);
    }

    /// Returns the number of raw digest computations for the registered blocks.
    pub fn count(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
impl Drop for DigestCounter {
    fn drop(&mut self) {
        let mut counters = DIGEST_COUNTERS.lock();
        for digest in &self.digests {
            counters.remove(digest);
        }
    }
}

/// A mock block with no explicit consensus context.
/// Its parent digest also serves as its certification context.
pub struct EmptyBlock<H: Hasher> {
    /// The parent block's digest.
    pub parent: H::Digest,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,
}

impl<H: Hasher> EmptyBlock<H> {
    pub const fn new(parent: H::Digest, height: Height, timestamp: u64) -> Self {
        Self {
            parent,
            height,
            timestamp,
        }
    }
}

impl<H: Hasher> Clone for EmptyBlock<H> {
    fn clone(&self) -> Self {
        Self {
            parent: self.parent,
            height: self.height,
            timestamp: self.timestamp,
        }
    }
}

impl<H: Hasher> Debug for EmptyBlock<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmptyBlock")
            .field("parent", &self.parent)
            .field("height", &self.height)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

impl<H: Hasher> PartialEq for EmptyBlock<H> {
    fn eq(&self, other: &Self) -> bool {
        self.parent == other.parent
            && self.height == other.height
            && self.timestamp == other.timestamp
    }
}

impl<H: Hasher> Eq for EmptyBlock<H> {}

impl<H: Hasher> Write for EmptyBlock<H> {
    fn write(&self, writer: &mut impl BufMut) {
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
    }
}

impl<H: Hasher> Read for EmptyBlock<H> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let parent = H::Digest::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.into();

        Ok(Self {
            parent,
            height,
            timestamp,
        })
    }
}

impl<H: Hasher> EncodeSize for EmptyBlock<H> {
    fn encode_size(&self) -> usize {
        self.parent.encode_size() + self.height.encode_size() + UInt(self.timestamp).encode_size()
    }
}

impl<H: Hasher> Digestible for EmptyBlock<H> {
    type Digest = H::Digest;

    fn digest(&self) -> H::Digest {
        H::hash(&[
            self.parent.as_ref(),
            &self.height.get().to_be_bytes(),
            &self.timestamp.to_be_bytes(),
        ])
    }
}

impl<H: Hasher> crate::Heightable for EmptyBlock<H> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<H: Hasher> crate::Block for EmptyBlock<H> {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<H: Hasher> crate::CertifiableBlock for EmptyBlock<H> {
    type Context = H::Digest;

    fn context(&self) -> Self::Context {
        self.parent
    }
}

impl<H: Hasher> crate::BoundedBlock for EmptyBlock<H> {
    fn max_encode_size(_: &Self::Cfg) -> Option<usize> {
        Some(H::Digest::SIZE + Height::MAX_ENCODE_SIZE + UInt::<u64>::MAX_ENCODE_SIZE)
    }
}

/// A mock block type for testing that stores consensus context.
///
/// The context type `C` should be the consensus context (e.g., `simplex::types::Context`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block<D: Digest, C> {
    /// The consensus context that was used when this block was proposed.
    pub context: C,

    /// The parent block's digest.
    pub parent: D,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,

    /// Pre-computed digest of the block.
    digest: D,
}

impl<D: Digest, C: Codec> Block<D, C> {
    fn compute_digest<H: Hasher<Digest = D>>(
        context: &C,
        parent: &D,
        height: Height,
        timestamp: u64,
    ) -> D {
        H::hash(&[
            parent.as_ref(),
            &height.get().to_be_bytes(),
            &context.encode(),
            &timestamp.to_be_bytes(),
        ])
    }

    pub fn new<H: Hasher<Digest = D>>(
        context: C,
        parent: D,
        height: Height,
        timestamp: u64,
    ) -> Self {
        let digest = Self::compute_digest::<H>(&context, &parent, height, timestamp);
        Self {
            context,
            parent,
            height,
            timestamp,
            digest,
        }
    }
}

impl<D: Digest, C: Write> Write for Block<D, C> {
    fn write(&self, writer: &mut impl BufMut) {
        self.context.write(writer);
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
        self.digest.write(writer);
    }
}

impl<D: Digest, C: Read<Cfg = ()>> Read for Block<D, C> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let context = C::read(reader)?;
        let parent = D::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.into();
        let digest = D::read(reader)?;

        Ok(Self {
            context,
            parent,
            height,
            timestamp,
            digest,
        })
    }
}

impl<D: Digest, C: EncodeSize> EncodeSize for Block<D, C> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.digest.encode_size()
    }
}

impl<D: Digest, C: Clone + Send + Sync + 'static> Digestible for Block<D, C> {
    type Digest = D;

    fn digest(&self) -> D {
        #[cfg(test)]
        if let Some(counter) = DIGEST_COUNTERS
            .lock()
            .get(self.digest.as_ref())
            .and_then(Weak::upgrade)
        {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        self.digest
    }
}

impl<D: Digest, C: Clone + Send + Sync + 'static> crate::Heightable for Block<D, C> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<D: Digest, C: Codec<Cfg = ()> + Clone + Send + Sync + 'static> crate::Block for Block<D, C> {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<D: Digest, C: Codec<Cfg = ()> + Clone + Send + Sync + 'static> crate::CertifiableBlock
    for Block<D, C>
{
    type Context = C;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl<D: Digest, C: Codec<Cfg = ()> + MaxEncodeSize + Clone + Send + Sync + 'static>
    crate::BoundedBlock for Block<D, C>
{
    fn max_encode_size(_: &Self::Cfg) -> Option<usize> {
        Some(
            C::MAX_ENCODE_SIZE
                + D::SIZE
                + Height::MAX_ENCODE_SIZE
                + UInt::<u64>::MAX_ENCODE_SIZE
                + D::SIZE,
        )
    }
}

/// A mock block whose codec configuration caps its encoded size, with `None` for no cap.
pub struct SizedBlock<C: Scheme, H: Hasher, P: PublicKey> {
    /// The consensus context that was used when this block was proposed. It names the parent by
    /// coding commitment, so the block can be the application block of both
    /// [`Standard`](crate::marshal::standard::Standard) and
    /// [`Coding`](crate::marshal::coding::Coding).
    pub context: Context<Commitment<Self, C, H>, P>,

    /// The parent block's digest.
    pub parent: H::Digest,
    /// The height of the block in the blockchain.
    pub height: Height,
    /// Arbitrary contents of any length, so a block can fill whatever cap its configuration sets.
    pub payload: Bytes,
}

impl<C: Scheme, H: Hasher, P: PublicKey> Clone for SizedBlock<C, H, P> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            parent: self.parent,
            height: self.height,
            payload: self.payload.clone(),
        }
    }
}

impl<C: Scheme, H: Hasher, P: PublicKey> Write for SizedBlock<C, H, P> {
    fn write(&self, writer: &mut impl BufMut) {
        self.context.write(writer);
        self.parent.write(writer);
        self.height.write(writer);
        self.payload.write(writer);
    }
}

impl<C: Scheme, H: Hasher, P: PublicKey> EncodeSize for SizedBlock<C, H, P> {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.payload.encode_size()
    }
}

impl<C: Scheme, H: Hasher, P: PublicKey> Read for SizedBlock<C, H, P> {
    type Cfg = Option<usize>;

    fn read_cfg(reader: &mut impl Buf, max_size: &Self::Cfg) -> Result<Self, Error> {
        let context = Context::read(reader)?;
        let parent = H::Digest::read(reader)?;
        let height = Height::read(reader)?;
        let payload = match max_size {
            Some(max_size) => Bytes::read_cfg(reader, &(..=*max_size).into())?,
            None => Bytes::read_cfg(reader, &(..).into())?,
        };
        let block = Self {
            context,
            parent,
            height,
            payload,
        };

        // The payload's range caps its allocation, and this check bounds the whole block.
        if max_size.is_some_and(|max_size| block.encode_size() > max_size) {
            return Err(Error::Invalid(
                "SizedBlock",
                "block exceeds the largest size",
            ));
        }
        Ok(block)
    }
}

impl<C: Scheme, H: Hasher, P: PublicKey> Digestible for SizedBlock<C, H, P> {
    type Digest = H::Digest;

    fn digest(&self) -> H::Digest {
        H::hash(&[&self.encode()])
    }
}

impl<C: Scheme, H: Hasher, P: PublicKey> crate::Heightable for SizedBlock<C, H, P> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<C: Scheme, H: Hasher, P: PublicKey> crate::Block for SizedBlock<C, H, P> {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl<C: Scheme, H: Hasher, P: PublicKey> crate::CertifiableBlock for SizedBlock<C, H, P> {
    type Context = Context<Commitment<Self, C, H>, P>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl<C: Scheme, H: Hasher, P: PublicKey> crate::BoundedBlock for SizedBlock<C, H, P> {
    fn max_encode_size(max_size: &Self::Cfg) -> Option<usize> {
        *max_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::coding::types::coding_config_for_participants,
        types::{Epoch, Round, View},
    };
    use commonware_codec::Decode;
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        Sha256, Signer,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
    };

    type TestSizedBlock = SizedBlock<ReedSolomon<Sha256>, Sha256, PublicKey>;

    /// A sized block decodes under a cap equal to its encoded size and fails under a cap one byte
    /// smaller, even though the payload alone fits that cap.
    #[test]
    fn sized_block_decodes_only_up_to_cap() {
        let parent = Commitment::<TestSizedBlock, ReedSolomon<Sha256>, Sha256>::from((
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            coding_config_for_participants(4),
        ));
        let block = TestSizedBlock {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: PrivateKey::from_seed(0).public_key(),
                parent: (View::zero(), parent),
            },
            parent: Sha256Digest::EMPTY,
            height: Height::new(1),
            payload: Bytes::from(vec![7u8; 16]),
        };
        let encoded = block.encode();
        let size = encoded.len();
        assert!(TestSizedBlock::decode_cfg(encoded.clone(), &Some(size)).is_ok());
        assert!(TestSizedBlock::decode_cfg(encoded.clone(), &Some(size - 1)).is_err());
        assert!(TestSizedBlock::decode_cfg(encoded, &None).is_ok());
    }
}
