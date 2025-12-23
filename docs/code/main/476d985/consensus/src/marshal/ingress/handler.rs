use crate::{types::Round, Block};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::Span;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
};
use tracing::error;

/// The subject of a backfill request.
const BLOCK_REQUEST: u8 = 0;
const FINALIZED_REQUEST: u8 = 1;
const NOTARIZED_REQUEST: u8 = 2;

/// Messages sent from the resolver's [Consumer]/[Producer] implementation
/// to the marshal [Actor](super::super::actor::Actor).
pub enum Message<B: Block> {
    /// A request to deliver a value for a given key.
    Deliver {
        /// The key of the value being delivered.
        key: Request<B>,
        /// The value being delivered.
        value: Bytes,
        /// A channel to send the result of the delivery (true for success).
        response: oneshot::Sender<bool>,
    },
    /// A request to produce a value for a given key.
    Produce {
        /// The key of the value to produce.
        key: Request<B>,
        /// A channel to send the produced value.
        response: oneshot::Sender<Bytes>,
    },
}

/// A handler that forwards requests from the resolver to the marshal actor.
///
/// This struct implements the [Consumer] and [Producer] traits from the
/// resolver, and acts as a bridge to the main actor loop.
#[derive(Clone)]
pub struct Handler<B: Block> {
    sender: mpsc::Sender<Message<B>>,
}

impl<B: Block> Handler<B> {
    /// Creates a new handler.
    pub const fn new(sender: mpsc::Sender<Message<B>>) -> Self {
        Self { sender }
    }
}

impl<B: Block> Consumer for Handler<B> {
    type Key = Request<B>;
    type Value = Bytes;
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Deliver {
                key,
                value,
                response,
            })
            .await
            .is_err()
        {
            error!("failed to send deliver message to actor: receiver dropped");
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    async fn failed(&mut self, _: Self::Key, _: Self::Failure) {
        // We don't need to do anything on failure, the resolver will retry.
    }
}

impl<B: Block> Producer for Handler<B> {
    type Key = Request<B>;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Produce { key, response })
            .await
            .is_err()
        {
            error!("failed to send produce message to actor: receiver dropped");
        }
        receiver
    }
}

/// A request for backfilling data.
#[derive(Clone)]
pub enum Request<B: Block> {
    Block(B::Commitment),
    Finalized { height: u64 },
    Notarized { round: Round },
}

impl<B: Block> Request<B> {
    /// The subject of the request.
    const fn subject(&self) -> u8 {
        match self {
            Self::Block(_) => BLOCK_REQUEST,
            Self::Finalized { .. } => FINALIZED_REQUEST,
            Self::Notarized { .. } => NOTARIZED_REQUEST,
        }
    }

    /// The predicate to use when pruning subjects related to this subject.
    ///
    /// Specifically, any subjects unrelated will be left unmodified. Any related
    /// subjects will be pruned if they are "less than or equal to" this subject.
    pub fn predicate(&self) -> impl Fn(&Self) -> bool + Send + 'static {
        let cloned = self.clone();
        move |s| match (&cloned, &s) {
            (Self::Block(_), _) => unreachable!("we should never retain by block"),
            (Self::Finalized { height: mine }, Self::Finalized { height: theirs }) => {
                *theirs > *mine
            }
            (Self::Finalized { .. }, _) => true,
            (Self::Notarized { round: mine }, Self::Notarized { round: theirs }) => *theirs > *mine,
            (Self::Notarized { .. }, _) => true,
        }
    }
}

impl<B: Block> Write for Request<B> {
    fn write(&self, buf: &mut impl BufMut) {
        self.subject().write(buf);
        match self {
            Self::Block(commitment) => commitment.write(buf),
            Self::Finalized { height } => height.write(buf),
            Self::Notarized { round } => round.write(buf),
        }
    }
}

impl<B: Block> Read for Request<B> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request = match u8::read(buf)? {
            BLOCK_REQUEST => Self::Block(B::Commitment::read(buf)?),
            FINALIZED_REQUEST => Self::Finalized {
                height: u64::read(buf)?,
            },
            NOTARIZED_REQUEST => Self::Notarized {
                round: Round::read(buf)?,
            },
            i => return Err(CodecError::InvalidEnum(i)),
        };
        Ok(request)
    }
}

impl<B: Block> EncodeSize for Request<B> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Block(block) => block.encode_size(),
            Self::Finalized { height } => height.encode_size(),
            Self::Notarized { round } => round.encode_size(),
        }
    }
}

impl<B: Block> Span for Request<B> {}

impl<B: Block> PartialEq for Request<B> {
    fn eq(&self, other: &Self) -> bool {
        match (&self, &other) {
            (Self::Block(a), Self::Block(b)) => a == b,
            (Self::Finalized { height: a }, Self::Finalized { height: b }) => a == b,
            (Self::Notarized { round: a }, Self::Notarized { round: b }) => a == b,
            _ => false,
        }
    }
}

impl<B: Block> Eq for Request<B> {}

impl<B: Block> Ord for Request<B> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (&self, &other) {
            (Self::Block(a), Self::Block(b)) => a.cmp(b),
            (Self::Finalized { height: a }, Self::Finalized { height: b }) => a.cmp(b),
            (Self::Notarized { round: a }, Self::Notarized { round: b }) => a.cmp(b),
            (a, b) => a.subject().cmp(&b.subject()),
        }
    }
}

impl<B: Block> PartialOrd for Request<B> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<B: Block> Hash for Request<B> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Block(commitment) => commitment.hash(state),
            Self::Finalized { height } => height.hash(state),
            Self::Notarized { round } => round.hash(state),
        }
    }
}

impl<B: Block> Display for Request<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(commitment) => write!(f, "Block({commitment:?})"),
            Self::Finalized { height } => write!(f, "Finalized({height:?})"),
            Self::Notarized { round } => write!(f, "Notarized({round:?})"),
        }
    }
}

impl<B: Block> Debug for Request<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(commitment) => write!(f, "Block({commitment:?})"),
            Self::Finalized { height } => write!(f, "Finalized({height:?})"),
            Self::Notarized { round } => write!(f, "Notarized({round:?})"),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<B: Block> arbitrary::Arbitrary<'_> for Request<B>
where
    B::Commitment: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => {
                let commitment = B::Commitment::arbitrary(u)?;
                Ok(Self::Block(commitment))
            }
            1 => {
                let height = u.arbitrary::<u64>()?;
                Ok(Self::Finalized { height })
            }
            2 => {
                let round = Round::arbitrary(u)?;
                Ok(Self::Notarized { round })
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::mocks::block::Block as TestBlock,
        types::{Epoch, View},
    };
    use commonware_codec::{Encode, ReadExt};
    use commonware_cryptography::{
        sha256::{Digest as Sha256Digest, Sha256},
        Hasher as _,
    };
    use std::collections::BTreeSet;

    type B = TestBlock<Sha256Digest>;

    #[test]
    fn test_subject_block_encoding() {
        let commitment = Sha256::hash(b"test");
        let request = Request::<B>::Block(commitment);

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded.len(), 33); // 1 byte for enum variant + 32 bytes for commitment
        assert_eq!(encoded[0], 0); // Block variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Request::<B>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Request::Block(commitment));
    }

    #[test]
    fn test_subject_finalized_encoding() {
        let height = 12345u64;
        let request = Request::<B>::Finalized { height };

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 1); // Finalized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Request::<B>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Request::Finalized { height });
    }

    #[test]
    fn test_subject_notarized_encoding() {
        let round = Round::new(Epoch::new(67890), View::new(12345));
        let request = Request::<B>::Notarized { round };

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 2); // Notarized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Request::<B>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Request::Notarized { round });
    }

    #[test]
    fn test_subject_hash() {
        use std::collections::HashSet;

        let r1 = Request::<B>::Finalized { height: 100 };
        let r2 = Request::<B>::Finalized { height: 100 };
        let r3 = Request::<B>::Finalized { height: 200 };

        let mut set = HashSet::new();
        set.insert(r1);
        assert!(!set.insert(r2)); // Should not insert duplicate
        assert!(set.insert(r3)); // Should insert different value
    }

    #[test]
    fn test_subject_predicate() {
        let r1 = Request::<B>::Finalized { height: 100 };
        let r2 = Request::<B>::Finalized { height: 200 };
        let r3 = Request::<B>::Notarized {
            round: Round::new(Epoch::new(333), View::new(150)),
        };

        let predicate = r1.predicate();
        assert!(predicate(&r2)); // r2.height > r1.height
        assert!(predicate(&r3)); // Different variant (notarized)

        let r1_same = Request::<B>::Finalized { height: 100 };
        assert!(!predicate(&r1_same)); // Same height, should not pass
    }

    #[test]
    fn test_encode_size() {
        let commitment = Sha256::hash(&[0u8; 32]);
        let r1 = Request::<B>::Block(commitment);
        let r2 = Request::<B>::Finalized { height: u64::MAX };
        let r3 = Request::<B>::Notarized {
            round: Round::new(Epoch::new(333), View::new(0)),
        };

        // Verify encode_size matches actual encoded length
        assert_eq!(r1.encode_size(), r1.encode().len());
        assert_eq!(r2.encode_size(), r2.encode().len());
        assert_eq!(r3.encode_size(), r3.encode().len());
    }

    #[test]
    fn test_request_ord_same_variant() {
        // Test ordering within the same variant
        let commitment1 = Sha256::hash(b"test1");
        let commitment2 = Sha256::hash(b"test2");
        let block1 = Request::<B>::Block(commitment1);
        let block2 = Request::<B>::Block(commitment2);

        // Block ordering depends on commitment ordering
        if commitment1 < commitment2 {
            assert!(block1 < block2);
            assert!(block2 > block1);
        } else {
            assert!(block1 > block2);
            assert!(block2 < block1);
        }

        // Finalized ordering by height
        let fin1 = Request::<B>::Finalized { height: 100 };
        let fin2 = Request::<B>::Finalized { height: 200 };
        let fin3 = Request::<B>::Finalized { height: 200 };

        assert!(fin1 < fin2);
        assert!(fin2 > fin1);
        assert_eq!(fin2.cmp(&fin3), std::cmp::Ordering::Equal);

        // Notarized ordering by view
        let not1 = Request::<B>::Notarized {
            round: Round::new(Epoch::new(333), View::new(50)),
        };
        let not2 = Request::<B>::Notarized {
            round: Round::new(Epoch::new(333), View::new(150)),
        };
        let not3 = Request::<B>::Notarized {
            round: Round::new(Epoch::new(333), View::new(150)),
        };

        assert!(not1 < not2);
        assert!(not2 > not1);
        assert_eq!(not2.cmp(&not3), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_request_ord_cross_variant() {
        let commitment = Sha256::hash(b"test");
        let block = Request::<B>::Block(commitment);
        let finalized = Request::<B>::Finalized { height: 100 };
        let notarized = Request::<B>::Notarized {
            round: Round::new(Epoch::new(333), View::new(200)),
        };

        // Block < Finalized < Notarized
        assert!(block < finalized);
        assert!(block < notarized);
        assert!(finalized < notarized);

        assert!(finalized > block);
        assert!(notarized > block);
        assert!(notarized > finalized);

        // Test all combinations
        assert_eq!(block.cmp(&finalized), std::cmp::Ordering::Less);
        assert_eq!(block.cmp(&notarized), std::cmp::Ordering::Less);
        assert_eq!(finalized.cmp(&notarized), std::cmp::Ordering::Less);
        assert_eq!(finalized.cmp(&block), std::cmp::Ordering::Greater);
        assert_eq!(notarized.cmp(&block), std::cmp::Ordering::Greater);
        assert_eq!(notarized.cmp(&finalized), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_request_partial_ord() {
        let commitment1 = Sha256::hash(b"test1");
        let commitment2 = Sha256::hash(b"test2");
        let block1 = Request::<B>::Block(commitment1);
        let block2 = Request::<B>::Block(commitment2);
        let finalized = Request::<B>::Finalized { height: 100 };
        let notarized = Request::<B>::Notarized {
            round: Round::new(Epoch::new(333), View::new(200)),
        };

        // PartialOrd should always return Some
        assert!(block1.partial_cmp(&block2).is_some());
        assert!(block1.partial_cmp(&finalized).is_some());
        assert!(finalized.partial_cmp(&notarized).is_some());

        // Verify consistency with Ord
        assert_eq!(
            block1.partial_cmp(&finalized),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            finalized.partial_cmp(&notarized),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            notarized.partial_cmp(&block1),
            Some(std::cmp::Ordering::Greater)
        );
    }

    #[test]
    fn test_request_ord_sorting() {
        let commitment1 = Sha256::hash(b"a");
        let commitment2 = Sha256::hash(b"b");
        let commitment3 = Sha256::hash(b"c");

        let requests = vec![
            Request::<B>::Notarized {
                round: Round::new(Epoch::new(333), View::new(300)),
            },
            Request::<B>::Block(commitment2),
            Request::<B>::Finalized { height: 200 },
            Request::<B>::Block(commitment1),
            Request::<B>::Notarized {
                round: Round::new(Epoch::new(333), View::new(250)),
            },
            Request::<B>::Finalized { height: 100 },
            Request::<B>::Block(commitment3),
        ];

        // Sort using BTreeSet (uses Ord)
        let sorted: Vec<_> = requests
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        // Verify order: all Blocks first (sorted by commitment), then Finalized (by height), then Notarized (by view)
        assert_eq!(sorted.len(), 7);

        // Check that all blocks come first
        assert!(matches!(sorted[0], Request::<B>::Block(_)));
        assert!(matches!(sorted[1], Request::<B>::Block(_)));
        assert!(matches!(sorted[2], Request::<B>::Block(_)));

        // Check that finalized come next
        assert_eq!(sorted[3], Request::<B>::Finalized { height: 100 });
        assert_eq!(sorted[4], Request::<B>::Finalized { height: 200 });

        // Check that notarized come last
        assert_eq!(
            sorted[5],
            Request::<B>::Notarized {
                round: Round::new(Epoch::new(333), View::new(250))
            }
        );
        assert_eq!(
            sorted[6],
            Request::<B>::Notarized {
                round: Round::new(Epoch::new(333), View::new(300))
            }
        );
    }

    #[test]
    fn test_request_ord_edge_cases() {
        // Test with extreme values
        let min_finalized = Request::<B>::Finalized { height: 0 };
        let max_finalized = Request::<B>::Finalized { height: u64::MAX };
        let min_notarized = Request::<B>::Notarized {
            round: Round::new(Epoch::new(333), View::new(0)),
        };
        let max_notarized = Request::<B>::Notarized {
            round: Round::new(Epoch::new(333), View::new(u64::MAX)),
        };

        assert!(min_finalized < max_finalized);
        assert!(min_notarized < max_notarized);
        assert!(max_finalized < min_notarized);

        // Test self-comparison
        let commitment = Sha256::hash(b"self");
        let block = Request::<B>::Block(commitment);
        assert_eq!(block.cmp(&block), std::cmp::Ordering::Equal);
        assert_eq!(min_finalized.cmp(&min_finalized), std::cmp::Ordering::Equal);
        assert_eq!(max_notarized.cmp(&max_notarized), std::cmp::Ordering::Equal);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Request<B>>,
        }
    }
}
