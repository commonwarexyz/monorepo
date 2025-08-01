use crate::Block;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_utils::Span;
use std::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::Deref,
};

/// The request sent to peers when backfilling notarizations, finalizations, and blocks.
#[derive(Clone)]
pub struct Request<B: Block> {
    /// The serialized bytes of the request.
    raw: Vec<u8>,

    /// Phantom data for the block type.
    _phantom: PhantomData<B>,
}

impl<B: Block> Request<B> {
    /// Parse request type from raw bytes.
    fn request_type(&self) -> u8 {
        self.raw[0]
    }

    /// Check if this is a block request.
    pub fn is_block(&self) -> bool {
        self.request_type() == 0
    }

    /// Check if this is a finalized request.
    pub fn is_finalized(&self) -> bool {
        self.request_type() == 1
    }

    /// Check if this is a notarized request.
    pub fn is_notarized(&self) -> bool {
        self.request_type() == 2
    }

    /// Get block commitment if this is a block request.
    pub fn block_commitment(&self) -> Option<B::Commitment> {
        if !self.is_block() {
            return None;
        }
        let mut buf = &self.raw[1..];
        B::Commitment::read(&mut buf).ok()
    }

    /// Get height if this is a finalized request.
    pub fn finalized_height(&self) -> Option<u64> {
        if !self.is_finalized() {
            return None;
        }
        let mut buf = &self.raw[1..];
        u64::read(&mut buf).ok()
    }

    /// Get view if this is a notarized request.
    pub fn notarized_view(&self) -> Option<u64> {
        if !self.is_notarized() {
            return None;
        }
        let mut buf = &self.raw[1..];
        u64::read(&mut buf).ok()
    }

    /// Create a predicate for pruning finalized requests.
    pub fn finalized_predicate(height: u64) -> impl Fn(&Request<B>) -> bool + Send + 'static {
        move |r| {
            if let Some(theirs) = r.finalized_height() {
                theirs > height
            } else {
                true
            }
        }
    }

    /// Create a predicate for pruning notarized requests.
    pub fn notarized_predicate(view: u64) -> impl Fn(&Request<B>) -> bool + Send + 'static {
        move |r| {
            if let Some(theirs) = r.notarized_view() {
                theirs > view
            } else {
                true
            }
        }
    }

    /// Create a [Request] for a block.
    pub fn block(commitment: B::Commitment) -> Self {
        let mut raw = Vec::with_capacity(1 + commitment.encode_size());
        0u8.write(&mut raw);
        commitment.write(&mut raw);
        Self {
            raw,
            _phantom: PhantomData,
        }
    }

    /// Create a [Request] for a finalization.
    pub fn finalized(height: u64) -> Self {
        let mut raw = Vec::with_capacity(1 + height.encode_size());
        1u8.write(&mut raw);
        height.write(&mut raw);
        Self {
            raw,
            _phantom: PhantomData,
        }
    }

    /// Create a [Request] for a notarization.
    pub fn notarized(view: u64) -> Self {
        let mut raw = Vec::with_capacity(1 + view.encode_size());
        2u8.write(&mut raw);
        view.write(&mut raw);
        Self {
            raw,
            _phantom: PhantomData,
        }
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
        // Read type byte
        let type_byte = u8::read(buf)?;

        // Read the payload and build raw bytes
        let mut raw = Vec::new();
        raw.push(type_byte);

        match type_byte {
            0 => {
                let commitment = B::Commitment::read(buf)?;
                commitment.write(&mut raw);
            }
            1 | 2 => {
                let value = u64::read(buf)?;
                value.write(&mut raw);
            }
            i => return Err(CodecError::InvalidEnum(i)),
        }

        Ok(Self {
            raw,
            _phantom: PhantomData,
        })
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
        match self.request_type() {
            0 => {
                if let Some(commitment) = self.block_commitment() {
                    write!(f, "Block({commitment:?})")
                } else {
                    write!(f, "Block(invalid)")
                }
            }
            1 => {
                if let Some(height) = self.finalized_height() {
                    write!(f, "Finalized({height})")
                } else {
                    write!(f, "Finalized(invalid)")
                }
            }
            2 => {
                if let Some(view) = self.notarized_view() {
                    write!(f, "Notarized({view})")
                } else {
                    write!(f, "Notarized(invalid)")
                }
            }
            _ => write!(f, "Unknown({})", self.request_type()),
        }
    }
}

impl<B: Block> Debug for Request<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
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
        assert!(decoded.is_block());
        assert_eq!(decoded.block_commitment(), Some(commitment));
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
        assert!(decoded.is_finalized());
        assert_eq!(decoded.finalized_height(), Some(height));
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
        assert!(decoded.is_notarized());
        assert_eq!(decoded.notarized_view(), Some(view));
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
    fn test_predicates() {
        let r1 = Request::<B>::finalized(100);
        let r2 = Request::<B>::finalized(200);
        let r3 = Request::<B>::notarized(150);

        let finalized_predicate = Request::<B>::finalized_predicate(100);
        assert!(finalized_predicate(&r2)); // r2.height > 100
        assert!(finalized_predicate(&r3)); // Different variant (notarized)

        let r1_same = Request::<B>::finalized(100);
        assert!(!finalized_predicate(&r1_same)); // Same height, should not pass

        let notarized_predicate = Request::<B>::notarized_predicate(150);
        let r4 = Request::<B>::notarized(200);
        let r5 = Request::<B>::notarized(150);
        assert!(notarized_predicate(&r4)); // r4.view > 150
        assert!(!notarized_predicate(&r5)); // Same view, should not pass
        assert!(notarized_predicate(&r1)); // Different variant (finalized)
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
