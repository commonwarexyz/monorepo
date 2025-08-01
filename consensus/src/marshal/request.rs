use crate::Block;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_utils::Span;
use std::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};

/// The subject of a [Request].
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum Subject<B: Block> {
    Block(B::Commitment),
    Finalized { height: u64 },
    Notarized { view: u64 },
}

impl<B: Block> Subject<B> {
    /// The predicate to use when pruning subjects related to this subject.
    ///
    /// Specifically, any subjects unrelated will be left unmodified. Any related
    /// subjects will be pruned if they are "less than" this subject.
    pub fn predicate(&self) -> impl Fn(&Request<B>) -> bool + Send + 'static {
        let cloned = self.clone();
        move |r| match (&cloned, &r.inner) {
            (Self::Block(_), _) => unreachable!("we should never prune by block"),
            (Self::Finalized { height: mine }, Self::Finalized { height: theirs }) => {
                *theirs > *mine
            }
            (Self::Finalized { .. }, _) => true,
            (Self::Notarized { view: mine }, Self::Notarized { view: theirs }) => *theirs > *mine,
            (Self::Notarized { .. }, _) => true,
        }
    }
}

impl<B: Block> Write for Subject<B> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Block(commitment) => {
                0u8.write(buf);
                commitment.write(buf)
            }
            Self::Finalized { height } => {
                1u8.write(buf);
                height.write(buf)
            }
            Self::Notarized { view } => {
                2u8.write(buf);
                view.write(buf)
            }
        }
    }
}

impl<B: Block> Read for Subject<B> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request = match u8::read(buf)? {
            0 => Self::Block(B::Commitment::read(buf)?),
            1 => Self::Finalized {
                height: u64::read(buf)?,
            },
            2 => Self::Notarized {
                view: u64::read(buf)?,
            },
            i => return Err(CodecError::InvalidEnum(i)),
        };
        Ok(request)
    }
}

impl<B: Block> EncodeSize for Subject<B> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Block(block) => block.encode_size(),
            Self::Finalized { height } => height.encode_size(),
            Self::Notarized { view } => view.encode_size(),
        }
    }
}

/// The request sent to peers when backfilling notarizations, finalizations, and blocks.
#[derive(Clone)]
pub struct Request<B: Block> {
    /// The subject of the request.
    inner: Subject<B>,

    /// The serialized bytes of the request.
    raw: Vec<u8>,
}

impl<B: Block> Request<B> {
    /// Create a new [Request] from an inner [Subject].
    pub fn new(inner: Subject<B>) -> Self {
        let mut raw = Vec::with_capacity(inner.encode_size());
        inner.write(&mut raw);
        Self { inner, raw }
    }

    /// Create a [Request] for a block.
    pub fn block(commitment: B::Commitment) -> Self {
        Self::new(Subject::Block(commitment))
    }

    /// Create a [Request] for a finalization.
    pub fn finalized(height: u64) -> Self {
        Self::new(Subject::Finalized { height })
    }

    /// Create a [Request] for a notarization.
    pub fn notarized(view: u64) -> Self {
        Self::new(Subject::Notarized { view })
    }

    /// Get the [Subject] of the [Request].
    pub fn subject(self) -> Subject<B> {
        self.inner
    }
}

impl<B: Block> Span for Request<B> {}

impl<B: Block> Write for Request<B> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.raw);
    }
}

impl<B: Block> Read for Request<B> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let inner = Subject::read_cfg(buf, &())?;
        Ok(Self::new(inner))
    }
}

impl<B: Block> EncodeSize for Request<B> {
    fn encode_size(&self) -> usize {
        self.raw.len()
    }
}

impl<B: Block> PartialEq for Request<B> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<B: Block> Eq for Request<B> {}

impl<B: Block> Ord for Request<B> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl<B: Block> PartialOrd for Request<B> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<B: Block> AsRef<[u8]> for Request<B> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl<B: Block> Deref for Request<B> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl<B: Block> Hash for Request<B> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl<B: Block> Display for Request<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Subject::Block(commitment) => write!(f, "Block({commitment:?})"),
            Subject::Finalized { height } => write!(f, "Finalized({height:?})"),
            Subject::Notarized { view } => write!(f, "Notarized({view:?})"),
        }
    }
}

impl<B: Block> Debug for Request<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Subject::Block(commitment) => write!(f, "Block({commitment:?})"),
            Subject::Finalized { height } => write!(f, "Finalized({height:?})"),
            Subject::Notarized { view } => write!(f, "Notarized({view:?})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::mocks::block::Block as TestBlock;
    use commonware_codec::{Encode, ReadExt};
    use commonware_cryptography::sha256::{self, Digest as Sha256Digest};

    type B = TestBlock<Sha256Digest>;

    #[test]
    fn test_request_block_encoding() {
        let commitment = sha256::hash(b"test");
        let request = Request::<B>::block(commitment);

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded.len(), 33); // 1 byte for enum variant + 32 bytes for commitment
        assert_eq!(encoded[0], 0); // Block variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Request::<B>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded.subject(), Subject::Block(commitment));
    }

    #[test]
    fn test_request_finalized_encoding() {
        let height = 12345u64;
        let request = Request::<B>::finalized(height);

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 1); // Finalized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Request::<B>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded.subject(), Subject::Finalized { height });
    }

    #[test]
    fn test_request_notarized_encoding() {
        let view = 67890u64;
        let request = Request::<B>::notarized(view);

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 2); // Notarized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Request::<B>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded.subject(), Subject::Notarized { view });
    }

    #[test]
    fn test_request_hash() {
        use std::collections::HashSet;

        let r1 = Request::<B>::finalized(100);
        let r2 = Request::<B>::finalized(100);
        let r3 = Request::<B>::finalized(200);

        let mut set = HashSet::new();
        set.insert(r1);
        assert!(!set.insert(r2)); // Should not insert duplicate
        assert!(set.insert(r3)); // Should insert different value
    }

    #[test]
    fn test_subject_predicate() {
        let r1 = Request::<B>::finalized(100);
        let r2 = Request::<B>::finalized(200);
        let r3 = Request::<B>::notarized(150);

        let predicate = r1.subject().predicate();
        assert!(predicate(&r2)); // r2.height > r1.height
        assert!(predicate(&r3)); // Different variant (notarized)

        let r1_same = Request::<B>::finalized(100);
        assert!(!predicate(&r1_same)); // Same height, should not pass
    }

    #[test]
    fn test_encode_size() {
        let commitment = sha256::hash(&[0u8; 32]);
        let r1 = Request::<B>::block(commitment);
        let r2 = Request::<B>::finalized(u64::MAX);
        let r3 = Request::<B>::notarized(0);

        // Verify encode_size matches actual encoded length
        assert_eq!(r1.encode_size(), r1.encode().len());
        assert_eq!(r2.encode_size(), r2.encode().len());
        assert_eq!(r3.encode_size(), r3.encode().len());
    }
}
