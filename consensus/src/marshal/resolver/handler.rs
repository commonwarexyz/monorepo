use crate::types::{Height, Round};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::Digest;
use commonware_resolver::{p2p::Producer, Consumer, Subscribers};
use commonware_utils::{
    channel::{mpsc, oneshot},
    Span,
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
/// to the marshal actor.
pub enum Message<D: Digest> {
    /// A request to deliver a value for a given key.
    Deliver {
        /// The subscribers attached to the resolved value.
        subscribers: Subscribers<Request<D>, ResolverSubscriber<D>>,
        /// The value being delivered.
        value: Bytes,
        /// A channel to send the result of the delivery.
        response: oneshot::Sender<bool>,
    },
    /// A request to produce a value for a given key.
    Produce {
        /// The key of the value to produce.
        key: Request<D>,
        /// A channel to send the produced value.
        response: oneshot::Sender<Bytes>,
    },
}

/// A handler that forwards requests from the resolver to the marshal actor.
///
/// This struct implements the [Consumer] and [Producer] traits from the
/// resolver, and acts as a bridge to the main actor loop.
#[derive(Clone)]
pub struct Handler<D: Digest> {
    sender: mpsc::Sender<Message<D>>,
}

impl<D: Digest> Handler<D> {
    /// Creates a new handler.
    pub const fn new(sender: mpsc::Sender<Message<D>>) -> Self {
        Self { sender }
    }
}

impl<D: Digest> Consumer for Handler<D> {
    type Key = Request<D>;
    type Subscriber = ResolverSubscriber<D>;
    type Value = Bytes;

    async fn deliver(
        &mut self,
        subscribers: Subscribers<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .sender
            .send(Message::Deliver {
                subscribers,
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
}

impl<D: Digest> Producer for Handler<D> {
    type Key = Request<D>;

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

/// Local processing context for a resolved block request.
///
/// The resolver request key is the peer-visible lookup. A subscriber is local
/// metadata attached to that lookup so marshal can decide how to process the
/// response after validating it against the request key. Multiple local
/// subscribers may share one peer request when they depend on the same block.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BlockFetchContext {
    /// A block requested only to satisfy certified ancestry verification.
    ///
    /// The expected height is known before the request from the child block.
    Ancestry { height: Height },
    /// A block requested from a certified round whose height is not known until
    /// the response block is decoded.
    ///
    /// This covers certified parent fetches by round and finalized-block fetches
    /// where the finalization names a commitment but not a height.
    Finalized { round: Round },
    /// A block requested while repairing an internal finalized-chain gap.
    ///
    /// The expected height is known before the request from the gap boundary.
    Repair { height: Height },
}

impl BlockFetchContext {
    /// Return the expected block height when it is known before the request.
    ///
    /// Round-bound fetches validate commitment immediately and can only learn
    /// height from the decoded block, so they cannot be pruned by height before
    /// the response arrives.
    pub(crate) const fn expected_height(&self) -> Option<Height> {
        match self {
            Self::Ancestry { height } | Self::Repair { height } => Some(*height),
            Self::Finalized { .. } => None,
        }
    }
}

/// A request for backfilling data.
#[derive(Clone, Copy)]
pub enum Request<D: Digest> {
    /// Fetch a block by consensus commitment.
    Block {
        commitment: D,
    },
    Finalized {
        height: Height,
    },
    Notarized {
        round: Round,
    },
}

impl<D: Digest> Request<D> {
    /// Return the block commitment, if this is a block request.
    pub const fn block_commitment(&self) -> Option<D> {
        match self {
            Self::Block { commitment } => Some(*commitment),
            _ => None,
        }
    }

    /// The subject of the request.
    const fn subject(&self) -> u8 {
        match self {
            Self::Block { .. } => BLOCK_REQUEST,
            Self::Finalized { .. } => FINALIZED_REQUEST,
            Self::Notarized { .. } => NOTARIZED_REQUEST,
        }
    }
}

/// A local subscriber for a resolver fetch.
///
/// `Request` is the default subscriber: the resolved response is valid for the
/// peer-visible request, but there is no extra local storage context. `Block`
/// records why marshal asked for a block so delivery can notify local waiters,
/// populate the verified ancestry cache, or finalize repaired data without
/// exposing that context to peers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResolverSubscriber<D: Digest> {
    /// A peer-visible request.
    Request(Request<D>),
    /// A locally annotated block fetch.
    Block {
        commitment: D,
        context: BlockFetchContext,
    },
}

impl<D: Digest> ResolverSubscriber<D> {
    /// Create a subscriber for a peer-visible request.
    pub const fn request(request: Request<D>) -> Self {
        Self::Request(request)
    }

    /// Create a subscriber for a locally annotated block request.
    pub const fn block(commitment: D, context: BlockFetchContext) -> Self {
        Self::Block {
            commitment,
            context,
        }
    }

    /// Return the block commitment, if this is a block request.
    pub const fn block_commitment(&self) -> Option<D> {
        match self {
            Self::Request(request) => request.block_commitment(),
            Self::Block { commitment, .. } => Some(*commitment),
        }
    }

    /// The predicate to use when pruning subjects related to this subject.
    ///
    /// Unrelated subjects are retained. Related subjects are pruned if they are
    /// "less than or equal to" this subscriber's floor. This keeps pending
    /// candidate waits out of the resolver entirely, drops height-bound block
    /// requests once the processed height passes them, and drops round-bound
    /// certified-parent fetches once their round is no longer useful.
    pub fn predicate(&self) -> impl Fn(&Self) -> bool + Send + 'static {
        let cloned = *self;
        move |s| match (&cloned, s) {
            (
                Self::Block {
                    commitment: mine,
                    context: mine_context,
                },
                Self::Block {
                    commitment: theirs,
                    context: their_context,
                },
            ) => mine != theirs || mine_context != their_context,
            (Self::Request(Request::Block { commitment: mine }), _) => {
                s.block_commitment() != Some(*mine)
            }
            (Self::Block { .. }, _) => true,
            (
                Self::Request(Request::Finalized { height: mine }),
                Self::Request(Request::Finalized { height: theirs }),
            ) => *theirs > *mine,
            (
                Self::Request(Request::Finalized { height: mine }),
                Self::Block {
                    context:
                        BlockFetchContext::Ancestry { height: theirs }
                        | BlockFetchContext::Repair { height: theirs },
                    ..
                },
            ) => *theirs > *mine,
            (Self::Request(Request::Finalized { .. }), _) => true,
            (
                Self::Request(Request::Notarized { round: mine }),
                Self::Request(Request::Notarized { round: theirs }),
            ) => *theirs > *mine,
            (
                Self::Request(Request::Notarized { round: mine }),
                Self::Block {
                    context: BlockFetchContext::Finalized { round: theirs },
                    ..
                },
            ) => *theirs > *mine,
            (Self::Request(Request::Notarized { .. }), _) => true,
        }
    }
}

impl<D: Digest> From<Request<D>> for ResolverSubscriber<D> {
    fn from(request: Request<D>) -> Self {
        Self::Request(request)
    }
}

impl<D: Digest> Write for Request<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.subject().write(buf);
        match self {
            Self::Block { commitment } => commitment.write(buf),
            Self::Finalized { height } => height.write(buf),
            Self::Notarized { round } => round.write(buf),
        }
    }
}

impl<D: Digest> Read for Request<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request = match u8::read(buf)? {
            BLOCK_REQUEST => Self::Block {
                commitment: D::read(buf)?,
            },
            FINALIZED_REQUEST => Self::Finalized {
                height: Height::read(buf)?,
            },
            NOTARIZED_REQUEST => Self::Notarized {
                round: Round::read(buf)?,
            },
            i => return Err(CodecError::InvalidEnum(i)),
        };
        Ok(request)
    }
}

impl<D: Digest> EncodeSize for Request<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Block { commitment } => commitment.encode_size(),
            Self::Finalized { height } => height.encode_size(),
            Self::Notarized { round } => round.encode_size(),
        }
    }
}

impl<D: Digest> Span for Request<D> {}

impl<D: Digest> PartialEq for Request<D> {
    fn eq(&self, other: &Self) -> bool {
        match (&self, &other) {
            (Self::Block { commitment: a }, Self::Block { commitment: b }) => a == b,
            (Self::Finalized { height: a }, Self::Finalized { height: b }) => a == b,
            (Self::Notarized { round: a }, Self::Notarized { round: b }) => a == b,
            _ => false,
        }
    }
}

impl<D: Digest> Eq for Request<D> {}

impl<D: Digest> Ord for Request<D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (&self, &other) {
            (Self::Block { commitment: a }, Self::Block { commitment: b }) => a.cmp(b),
            (Self::Finalized { height: a }, Self::Finalized { height: b }) => a.cmp(b),
            (Self::Notarized { round: a }, Self::Notarized { round: b }) => a.cmp(b),
            (a, b) => a.subject().cmp(&b.subject()),
        }
    }
}

impl<D: Digest> PartialOrd for Request<D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<D: Digest> Hash for Request<D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.subject().hash(state);
        match self {
            Self::Block { commitment } => commitment.hash(state),
            Self::Finalized { height } => height.hash(state),
            Self::Notarized { round } => round.hash(state),
        }
    }
}

impl<D: Digest> Display for Request<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block { commitment } => write!(f, "Block({commitment:?})"),
            Self::Finalized { height } => write!(f, "Finalized({height:?})"),
            Self::Notarized { round } => write!(f, "Notarized({round:?})"),
        }
    }
}

impl<D: Digest> Debug for Request<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block { commitment } => write!(f, "Block({commitment:?})"),
            Self::Finalized { height } => write!(f, "Finalized({height:?})"),
            Self::Notarized { round } => write!(f, "Notarized({round:?})"),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Request<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => {
                let commitment = u.arbitrary()?;
                Ok(Self::Block { commitment })
            }
            1 => Ok(Self::Finalized {
                height: u.arbitrary()?,
            }),
            2 => Ok(Self::Notarized {
                round: u.arbitrary()?,
            }),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Epoch, View};
    use commonware_codec::{Encode, ReadExt};
    use commonware_cryptography::{
        sha256::{Digest as Sha256Digest, Sha256},
        Hasher as _,
    };
    use std::collections::BTreeSet;

    type D = Sha256Digest;

    const fn block(digest: D) -> Request<D> {
        Request::Block { commitment: digest }
    }

    #[test]
    fn test_cross_variant_hash_differs() {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };

        fn hash_of<T: Hash>(t: &T) -> u64 {
            let mut h = DefaultHasher::new();
            t.hash(&mut h);
            h.finish()
        }

        let finalized = Request::<D>::Finalized {
            height: Height::new(1),
        };
        let notarized = Request::<D>::Notarized {
            round: Round::new(Epoch::new(0), View::new(1)),
        };
        assert_ne!(hash_of(&finalized), hash_of(&notarized));
    }

    #[test]
    fn test_subject_block_encoding() {
        let digest = Sha256::hash(b"test");
        let request = Request::Block { commitment: digest };

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded.len(), 33); // 1 byte for enum variant + 32 bytes for digest
        assert_eq!(encoded[0], 0); // Block variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Request::<D>::read(&mut buf).unwrap();
        assert_eq!(decoded, block(digest));
        assert_eq!(request.encode(), decoded.encode());
    }

    #[test]
    fn test_subject_finalized_encoding() {
        let height = Height::new(12345u64);
        let request = Request::<D>::Finalized { height };

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 1); // Finalized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Request::<D>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Request::Finalized { height });
    }

    #[test]
    fn test_subject_notarized_encoding() {
        let round = Round::new(Epoch::new(67890), View::new(12345));
        let request = Request::<D>::Notarized { round };

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 2); // Notarized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Request::<D>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Request::Notarized { round });
    }

    #[test]
    fn test_subject_decode_rejects_invalid_enum_tag() {
        let bad = [3u8];
        let mut buf = bad.as_ref();
        assert!(matches!(
            Request::<D>::read(&mut buf),
            Err(CodecError::InvalidEnum(3))
        ));
    }

    #[test]
    fn test_subject_hash() {
        use std::collections::HashSet;

        let r1 = Request::<D>::Finalized {
            height: Height::new(100),
        };
        let r2 = Request::<D>::Finalized {
            height: Height::new(100),
        };
        let r3 = Request::<D>::Finalized {
            height: Height::new(200),
        };

        let mut set = HashSet::new();
        set.insert(r1);
        assert!(!set.insert(r2)); // Should not insert duplicate
        assert!(set.insert(r3)); // Should insert different value
    }

    #[test]
    fn test_subject_predicate() {
        let r1 = Request::<D>::Finalized {
            height: Height::new(100),
        };
        let r2 = Request::<D>::Finalized {
            height: Height::new(200),
        };
        let r3 = Request::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(150)),
        };

        let predicate = ResolverSubscriber::request(r1).predicate();
        assert!(predicate(&ResolverSubscriber::request(r2))); // r2.height > r1.height
        assert!(predicate(&ResolverSubscriber::request(r3))); // Different variant (notarized)

        let r1_same = Request::<D>::Finalized {
            height: Height::new(100),
        };
        assert!(!predicate(&ResolverSubscriber::request(r1_same))); // Same height, should not pass
    }

    #[test]
    fn test_block_subscriber_context_affects_identity() {
        let digest = Sha256::hash(b"annotated");
        let ancestry = ResolverSubscriber::block(
            digest,
            BlockFetchContext::Ancestry {
                height: Height::new(10),
            },
        );
        let repair = ResolverSubscriber::block(
            digest,
            BlockFetchContext::Repair {
                height: Height::new(10),
            },
        );

        assert_ne!(ancestry, repair);
        assert_eq!(ancestry.block_commitment(), repair.block_commitment());
    }

    #[test]
    fn test_subject_predicate_prunes_annotated_blocks() {
        let digest = Sha256::hash(b"prune");
        let height_floor = ResolverSubscriber::request(Request::<D>::Finalized {
            height: Height::new(10),
        });
        let keep_repair = ResolverSubscriber::block(
            digest,
            BlockFetchContext::Repair {
                height: Height::new(11),
            },
        );
        let drop_repair = ResolverSubscriber::block(
            digest,
            BlockFetchContext::Repair {
                height: Height::new(10),
            },
        );
        let drop_ancestry = ResolverSubscriber::block(
            digest,
            BlockFetchContext::Ancestry {
                height: Height::new(9),
            },
        );

        let predicate = height_floor.predicate();
        assert!(predicate(&keep_repair));
        assert!(!predicate(&drop_repair));
        assert!(!predicate(&drop_ancestry));

        let round_floor = ResolverSubscriber::request(Request::<D>::Notarized {
            round: Round::new(Epoch::new(1), View::new(10)),
        });
        let keep_finalized = ResolverSubscriber::block(
            digest,
            BlockFetchContext::Finalized {
                round: Round::new(Epoch::new(1), View::new(11)),
            },
        );
        let drop_finalized = ResolverSubscriber::block(
            digest,
            BlockFetchContext::Finalized {
                round: Round::new(Epoch::new(1), View::new(10)),
            },
        );

        let predicate = round_floor.predicate();
        assert!(predicate(&keep_finalized));
        assert!(!predicate(&drop_finalized));
    }

    #[test]
    fn test_encode_size() {
        let digest = Sha256::hash(&[0u8; 32]);
        let r1 = Request::Block { commitment: digest };
        let r2 = Request::<D>::Finalized {
            height: Height::new(u64::MAX),
        };
        let r3 = Request::<D>::Notarized {
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
        let digest1 = Sha256::hash(b"test1");
        let digest2 = Sha256::hash(b"test2");
        let block1 = block(digest1);
        let block2 = block(digest2);

        // Block ordering depends on digest ordering
        if digest1 < digest2 {
            assert!(block1 < block2);
            assert!(block2 > block1);
        } else {
            assert!(block1 > block2);
            assert!(block2 < block1);
        }

        // Finalized ordering by height
        let fin1 = Request::<D>::Finalized {
            height: Height::new(100),
        };
        let fin2 = Request::<D>::Finalized {
            height: Height::new(200),
        };
        let fin3 = Request::<D>::Finalized {
            height: Height::new(200),
        };

        assert!(fin1 < fin2);
        assert!(fin2 > fin1);
        assert_eq!(fin2.cmp(&fin3), std::cmp::Ordering::Equal);

        // Notarized ordering by view
        let not1 = Request::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(50)),
        };
        let not2 = Request::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(150)),
        };
        let not3 = Request::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(150)),
        };

        assert!(not1 < not2);
        assert!(not2 > not1);
        assert_eq!(not2.cmp(&not3), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_request_ord_cross_variant() {
        let digest = Sha256::hash(b"test");
        let block = block(digest);
        let finalized = Request::<D>::Finalized {
            height: Height::new(100),
        };
        let notarized = Request::<D>::Notarized {
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
        let digest1 = Sha256::hash(b"test1");
        let digest2 = Sha256::hash(b"test2");
        let block1 = block(digest1);
        let block2 = block(digest2);
        let finalized = Request::<D>::Finalized {
            height: Height::new(100),
        };
        let notarized = Request::<D>::Notarized {
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
        let digest1 = Sha256::hash(b"a");
        let digest2 = Sha256::hash(b"b");
        let digest3 = Sha256::hash(b"c");

        let requests = vec![
            Request::<D>::Notarized {
                round: Round::new(Epoch::new(333), View::new(300)),
            },
            block(digest2),
            Request::<D>::Finalized {
                height: Height::new(200),
            },
            block(digest1),
            Request::<D>::Notarized {
                round: Round::new(Epoch::new(333), View::new(250)),
            },
            Request::<D>::Finalized {
                height: Height::new(100),
            },
            block(digest3),
        ];

        // Sort using BTreeSet (uses Ord)
        let sorted: Vec<_> = requests
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        // Verify order: all Blocks first (sorted by digest), then Finalized (by height), then Notarized (by view)
        assert_eq!(sorted.len(), 7);

        // Check that all blocks come first
        assert!(sorted[0].block_commitment().is_some());
        assert!(sorted[1].block_commitment().is_some());
        assert!(sorted[2].block_commitment().is_some());

        // Check that finalized come next
        assert_eq!(
            sorted[3],
            Request::<D>::Finalized {
                height: Height::new(100)
            }
        );
        assert_eq!(
            sorted[4],
            Request::<D>::Finalized {
                height: Height::new(200)
            }
        );

        // Check that notarized come last
        assert_eq!(
            sorted[5],
            Request::<D>::Notarized {
                round: Round::new(Epoch::new(333), View::new(250))
            }
        );
        assert_eq!(
            sorted[6],
            Request::<D>::Notarized {
                round: Round::new(Epoch::new(333), View::new(300))
            }
        );
    }

    #[test]
    fn test_request_ord_edge_cases() {
        // Test with extreme values
        let min_finalized = Request::<D>::Finalized {
            height: Height::new(0),
        };
        let max_finalized = Request::<D>::Finalized {
            height: Height::new(u64::MAX),
        };
        let min_notarized = Request::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(0)),
        };
        let max_notarized = Request::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(u64::MAX)),
        };

        assert!(min_finalized < max_finalized);
        assert!(min_notarized < max_notarized);
        assert!(max_finalized < min_notarized);

        // Test self-comparison
        let digest = Sha256::hash(b"self");
        let block = block(digest);
        assert_eq!(block.cmp(&block), std::cmp::Ordering::Equal);
        assert_eq!(min_finalized.cmp(&min_finalized), std::cmp::Ordering::Equal);
        assert_eq!(max_notarized.cmp(&max_notarized), std::cmp::Ordering::Equal);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Request<D>>
        }
    }
}
