use crate::Block;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_utils::Span;
use std::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
};

/// The subject of a [Request].
#[derive(Clone)]
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
    pub fn predicate(&self) -> impl Fn(&Subject<B>) -> bool + Send + 'static {
        let cloned = self.clone();
        move |s| match (&cloned, &s) {
            (Self::Block(_), _) => unreachable!("we should never retain by block"),
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

impl<B: Block> Span for Subject<B> {}

impl<B: Block> PartialEq for Subject<B> {
    fn eq(&self, other: &Self) -> bool {
        match (&self, &other) {
            (Self::Block(a), Self::Block(b)) => a == b,
            (Self::Finalized { height: a }, Self::Finalized { height: b }) => a == b,
            (Self::Notarized { view: a }, Self::Notarized { view: b }) => a == b,
            _ => false,
        }
    }
}

impl<B: Block> Eq for Subject<B> {}

impl<B: Block> Ord for Subject<B> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (&self, &other) {
            (Self::Block(a), Self::Block(b)) => a.cmp(b),
            (Self::Finalized { height: a }, Self::Finalized { height: b }) => a.cmp(b),
            (Self::Notarized { view: a }, Self::Notarized { view: b }) => a.cmp(b),
            (Self::Block(_), Self::Finalized { .. }) => std::cmp::Ordering::Less,
            (Self::Block(_), Self::Notarized { .. }) => std::cmp::Ordering::Less,
            (Self::Finalized { .. }, Self::Notarized { .. }) => std::cmp::Ordering::Less,
            (Self::Finalized { .. }, Self::Block(_)) => std::cmp::Ordering::Greater,
            (Self::Notarized { .. }, Self::Block(_)) => std::cmp::Ordering::Greater,
            (Self::Notarized { .. }, Self::Finalized { .. }) => std::cmp::Ordering::Greater,
        }
    }
}

impl<B: Block> PartialOrd for Subject<B> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<B: Block> Hash for Subject<B> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Block(commitment) => commitment.hash(state),
            Self::Finalized { height } => height.hash(state),
            Self::Notarized { view } => view.hash(state),
        }
    }
}

impl<B: Block> Display for Subject<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(commitment) => write!(f, "Block({commitment:?})"),
            Self::Finalized { height } => write!(f, "Finalized({height:?})"),
            Self::Notarized { view } => write!(f, "Notarized({view:?})"),
        }
    }
}

impl<B: Block> Debug for Subject<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(commitment) => write!(f, "Block({commitment:?})"),
            Self::Finalized { height } => write!(f, "Finalized({height:?})"),
            Self::Notarized { view } => write!(f, "Notarized({view:?})"),
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
    fn test_subject_block_encoding() {
        let commitment = sha256::hash(b"test");
        let request = Subject::<B>::Block(commitment);

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded.len(), 33); // 1 byte for enum variant + 32 bytes for commitment
        assert_eq!(encoded[0], 0); // Block variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Subject::<B>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Subject::Block(commitment));
    }

    #[test]
    fn test_subject_finalized_encoding() {
        let height = 12345u64;
        let request = Subject::<B>::Finalized { height };

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 1); // Finalized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Subject::<B>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Subject::Finalized { height });
    }

    #[test]
    fn test_subject_notarized_encoding() {
        let view = 67890u64;
        let request = Subject::<B>::Notarized { view };

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 2); // Notarized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Subject::<B>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Subject::Notarized { view });
    }

    #[test]
    fn test_subject_hash() {
        use std::collections::HashSet;

        let r1 = Subject::<B>::Finalized { height: 100 };
        let r2 = Subject::<B>::Finalized { height: 100 };
        let r3 = Subject::<B>::Finalized { height: 200 };

        let mut set = HashSet::new();
        set.insert(r1);
        assert!(!set.insert(r2)); // Should not insert duplicate
        assert!(set.insert(r3)); // Should insert different value
    }

    #[test]
    fn test_subject_predicate() {
        let r1 = Subject::<B>::Finalized { height: 100 };
        let r2 = Subject::<B>::Finalized { height: 200 };
        let r3 = Subject::<B>::Notarized { view: 150 };

        let predicate = r1.subject().predicate();
        assert!(predicate(&r2)); // r2.height > r1.height
        assert!(predicate(&r3)); // Different variant (notarized)

        let r1_same = Subject::<B>::Finalized { height: 100 };
        assert!(!predicate(&r1_same)); // Same height, should not pass
    }

    #[test]
    fn test_encode_size() {
        let commitment = sha256::hash(&[0u8; 32]);
        let r1 = Subject::<B>::Block(commitment);
        let r2 = Subject::<B>::Finalized { height: u64::MAX };
        let r3 = Subject::<B>::Notarized { view: 0 };

        // Verify encode_size matches actual encoded length
        assert_eq!(r1.encode_size(), r1.encode().len());
        assert_eq!(r2.encode_size(), r2.encode().len());
        assert_eq!(r3.encode_size(), r3.encode().len());
    }
}
