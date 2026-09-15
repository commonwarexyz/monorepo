use crate::types::Height;
use commonware_codec::{Codec, EncodeSize, Read, Write, varint::UInt};
use commonware_cryptography::{Digest, Digestible, Hasher};
use std::fmt::Debug;

/// A mock block with no explicit consensus context.
/// Its parent digest also serves as its certification context.
#[derive(Write, Read, EncodeSize)]
pub struct EmptyBlock<H: Hasher> {
    /// The parent block's digest.
    pub parent: H::Digest,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    #[codec(
        encode_with = { UInt(*value).write(buf); },
        encode_size = UInt(*value).encode_size(),
        read_with = { Ok(UInt::read_cfg(buf, &())?.into()) }
    )]
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

/// A mock block type for testing that stores consensus context.
///
/// The context type `C` should be the consensus context (e.g., `simplex::types::Context`).
#[derive(Clone, Debug, PartialEq, Eq, Write, Read, EncodeSize)]
#[codec(read_bounds(C: Read<Cfg = ()>))]
pub struct Block<D: Digest, C> {
    /// The consensus context that was used when this block was proposed.
    pub context: C,

    /// The parent block's digest.
    pub parent: D,

    /// The height of the block in the blockchain.
    pub height: Height,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    #[codec(
        encode_with = { UInt(*value).write(buf); },
        encode_size = UInt(*value).encode_size(),
        read_with = { Ok(UInt::read_cfg(buf, &())?.into()) }
    )]
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

impl<D: Digest, C: Clone + Send + Sync + 'static> Digestible for Block<D, C> {
    type Digest = D;

    fn digest(&self) -> D {
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
