//! Internal handler types for resolver actor coordination.

use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Digest;
use commonware_resolver::{self as resolver, p2p::Producer};
use commonware_storage::merkle::{Family, Location, Proof, MAX_PROOF_DIGESTS_PER_ELEMENT};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    Span,
};
use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    num::NonZeroU64,
};

/// Safe upper bound on pinned nodes for any u64-backed family.
const MAX_PINNED_NODES: usize = 64;

/// Request key sent through `resolver::p2p::Engine`.
#[derive(Clone, Debug)]
pub(super) struct Request<F: Family> {
    /// Total operation count for proof context.
    pub op_count: Location<F>,
    /// First operation location to fetch.
    pub start_loc: Location<F>,
    /// Maximum number of operations to fetch.
    pub max_ops: NonZeroU64,
    /// Include pinned nodes for `start_loc` when `true`.
    pub include_pinned_nodes: bool,
}

impl<F: Family> PartialEq for Request<F> {
    fn eq(&self, other: &Self) -> bool {
        self.op_count == other.op_count
            && self.start_loc == other.start_loc
            && self.max_ops == other.max_ops
            && self.include_pinned_nodes == other.include_pinned_nodes
    }
}

impl<F: Family> Eq for Request<F> {}

impl<F: Family> PartialOrd for Request<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: Family> Ord for Request<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.op_count
            .cmp(&other.op_count)
            .then_with(|| self.start_loc.cmp(&other.start_loc))
            .then_with(|| self.max_ops.cmp(&other.max_ops))
            .then_with(|| self.include_pinned_nodes.cmp(&other.include_pinned_nodes))
    }
}

impl<F: Family> Hash for Request<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.op_count.hash(state);
        self.start_loc.hash(state);
        self.max_ops.hash(state);
        self.include_pinned_nodes.hash(state);
    }
}

impl<F: Family> fmt::Display for Request<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Request(count={}, start={}, max={}, pinned={})",
            self.op_count, self.start_loc, self.max_ops, self.include_pinned_nodes,
        )
    }
}

impl<F: Family> Write for Request<F> {
    fn write(&self, buf: &mut impl BufMut) {
        self.op_count.write(buf);
        self.start_loc.write(buf);
        self.max_ops.write(buf);
        self.include_pinned_nodes.write(buf);
    }
}

impl<F: Family> EncodeSize for Request<F> {
    fn encode_size(&self) -> usize {
        self.op_count.encode_size()
            + self.start_loc.encode_size()
            + self.max_ops.encode_size()
            + self.include_pinned_nodes.encode_size()
    }
}

impl<F: Family> Read for Request<F> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            op_count: Location::<F>::read(buf)?,
            start_loc: Location::<F>::read(buf)?,
            max_ops: NonZeroU64::read(buf)?,
            include_pinned_nodes: bool::read(buf)?,
        })
    }
}

impl<F: Family> Span for Request<F> {}

#[cfg(feature = "arbitrary")]
impl<F: Family> arbitrary::Arbitrary<'_> for Request<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            op_count: u.arbitrary()?,
            start_loc: u.arbitrary()?,
            max_ops: u.arbitrary()?,
            include_pinned_nodes: u.arbitrary()?,
        })
    }
}

/// Wire-format response to a [`Request`].
///
/// Carries the inclusion proof, the fetched operations, and
/// optionally the pinned nodes at the requested start location.
/// Encoded by the producing peer and decoded by the consuming peer;
/// the actor converts this into a [`FetchResult`](commonware_storage::qmdb::sync::resolver::FetchResult)
/// before handing it to subscribers.
pub(super) struct Response<F: Family, Op, D: Digest> {
    pub(super) proof: Proof<F, D>,
    pub(super) operations: Vec<Op>,
    pub(super) pinned_nodes: Option<Vec<D>>,
}

impl<F: Family, Op: Write, D: Digest> Write for Response<F, Op, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.operations.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl<F: Family, Op: EncodeSize, D: Digest> EncodeSize for Response<F, Op, D> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.operations.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl<F: Family, Op: Read<Cfg = ()>, D: Digest> Read for Response<F, Op, D> {
    /// Maximum operations expected in this response, derived from the
    /// request's `max_ops` field.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_ops: &usize) -> Result<Self, CodecError> {
        let max_proof_digests = max_ops.saturating_mul(MAX_PROOF_DIGESTS_PER_ELEMENT);
        let proof = Proof::<F, D>::read_cfg(buf, &max_proof_digests)?;
        let operations = Vec::<Op>::read_range(buf, ..=*max_ops)?;
        // Pinned nodes are the fold-prefix peaks at `start_loc`, independent of
        // `max_ops`. Bound them by the global pinned-node limit.
        let pinned_nodes = Option::<Vec<D>>::read_range(buf, ..=MAX_PINNED_NODES)?;
        Ok(Self {
            proof,
            operations,
            pinned_nodes,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, Op, D: Digest> arbitrary::Arbitrary<'_> for Response<F, Op, D>
where
    Op: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            proof: u.arbitrary()?,
            operations: u.arbitrary()?,
            pinned_nodes: u.arbitrary()?,
        })
    }
}

/// Messages sent from [`Handler`] to the resolver [`Actor`](super::Actor).
///
/// Each variant corresponds to one of the `resolver::Consumer` or `p2p::Producer`
/// callbacks, re-routed so the actor processes them on its own task.
pub(super) enum EngineMessage<F: Family> {
    /// A peer delivered a response for a previously fetched key.
    /// The actor decodes the value, fans it out to waiting subscribers,
    /// and reports acceptance back through `response`.
    Deliver {
        key: Request<F>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    /// A peer requested data for `key`.
    /// The actor queries the local database and sends the encoded
    /// [`Response`] back through `response`.
    Produce {
        key: Request<F>,
        response: oneshot::Sender<Bytes>,
    },
}

/// Bridges `resolver::Consumer` and `p2p::Producer` into the actor's
/// message channel.
///
/// Every callback from the resolver engine is converted into an
/// [`EngineMessage`] and sent to the actor. This keeps all mutable
/// state (pending subscribers, database handle) on the actor task,
/// while the engine runs independently.
#[derive(Clone)]
pub(super) struct Handler<F: Family> {
    sender: mpsc::Sender<EngineMessage<F>>,
}

impl<F: Family> Handler<F> {
    pub(super) const fn new(sender: mpsc::Sender<EngineMessage<F>>) -> Self {
        Self { sender }
    }
}

impl<F: Family> resolver::Consumer for Handler<F> {
    type Key = Request<F>;
    type Value = Bytes;

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        self.sender
            .request_or(
                |response| EngineMessage::Deliver {
                    key,
                    value,
                    response,
                },
                false,
            )
            .await
    }
}

impl<F: Family> Producer for Handler<F> {
    type Key = Request<F>;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(EngineMessage::Produce { key, response })
            .await;
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::sha256;
    use commonware_storage::merkle::mmr;

    const TEST_MAX_OPS: usize = 10_000;

    #[test]
    fn response_codec_roundtrip() {
        let response = Response::<mmr::Family, u64, sha256::Digest> {
            proof: Proof {
                leaves: mmr::Location::new(10),
                inactive_peaks: 0,
                digests: vec![sha256::Digest::from([7; 32])],
            },
            operations: vec![1, 2, 3],
            pinned_nodes: Some(vec![sha256::Digest::from([9; 32])]),
        };

        let encoded = response.encode();
        let decoded =
            Response::<mmr::Family, u64, sha256::Digest>::decode_cfg(encoded, &TEST_MAX_OPS)
                .unwrap();
        assert_eq!(decoded.operations, vec![1, 2, 3]);
        assert_eq!(decoded.proof.leaves, mmr::Location::new(10));
        assert_eq!(decoded.pinned_nodes.unwrap().len(), 1);
    }

    #[test]
    fn response_decode_rejects_invalid_pinned_flag() {
        let mut encoded = Response::<mmr::Family, u64, sha256::Digest> {
            proof: Proof {
                leaves: mmr::Location::new(10),
                inactive_peaks: 0,
                digests: vec![sha256::Digest::from([7; 32])],
            },
            operations: vec![1, 2, 3],
            pinned_nodes: None,
        }
        .encode()
        .to_vec();
        *encoded
            .last_mut()
            .expect("response encoding must include pinned_nodes flag") = 2;

        let err = match Response::<mmr::Family, u64, sha256::Digest>::decode_cfg(
            Bytes::from(encoded),
            &TEST_MAX_OPS,
        ) {
            Ok(_) => panic!("decode should fail for invalid bool flag"),
            Err(err) => err,
        };
        assert!(matches!(err, CodecError::InvalidBool));
    }

    #[test]
    fn response_decode_allows_pinned_nodes_above_max_ops() {
        let max_ops = 1usize;
        let response = Response::<mmr::Family, u64, sha256::Digest> {
            proof: Proof {
                leaves: mmr::Location::new(10),
                inactive_peaks: 0,
                digests: vec![sha256::Digest::from([7; 32])],
            },
            operations: vec![1],
            pinned_nodes: Some(vec![sha256::Digest::from([9; 32]); 3]),
        };

        let encoded = response.encode();
        let decoded =
            Response::<mmr::Family, u64, sha256::Digest>::decode_cfg(encoded, &max_ops).unwrap();
        assert_eq!(decoded.operations, vec![1]);
        assert_eq!(decoded.pinned_nodes.unwrap().len(), 3);
    }

    #[test]
    fn response_decode_allows_max_single_operation_proof() {
        let max_ops = 1usize;
        let response = Response::<mmr::Family, u64, sha256::Digest> {
            proof: Proof {
                leaves: mmr::Location::new(10),
                inactive_peaks: 0,
                digests: vec![sha256::Digest::from([7; 32]); MAX_PROOF_DIGESTS_PER_ELEMENT],
            },
            operations: vec![1],
            pinned_nodes: None,
        };

        let encoded = response.encode();
        let decoded =
            Response::<mmr::Family, u64, sha256::Digest>::decode_cfg(encoded, &max_ops).unwrap();
        assert_eq!(decoded.operations, vec![1]);
        assert_eq!(decoded.proof.digests.len(), MAX_PROOF_DIGESTS_PER_ELEMENT);
    }

    #[test]
    fn request_codec_roundtrip() {
        let req = Request::<mmr::Family> {
            op_count: mmr::Location::new(128),
            start_loc: mmr::Location::new(64),
            max_ops: NonZeroU64::new(16).unwrap(),
            include_pinned_nodes: true,
        };
        let encoded = req.encode();
        let decoded = Request::<mmr::Family>::decode(encoded).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn request_decode_rejects_invalid_pinned_flag() {
        let mut encoded = Request::<mmr::Family> {
            op_count: mmr::Location::new(128),
            start_loc: mmr::Location::new(64),
            max_ops: NonZeroU64::new(16).unwrap(),
            include_pinned_nodes: true,
        }
        .encode()
        .to_vec();
        *encoded
            .last_mut()
            .expect("request encoding must include flag") = 2;

        let err = Request::<mmr::Family>::decode(Bytes::from(encoded)).unwrap_err();
        assert!(matches!(err, CodecError::InvalidBool));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Request<mmr::Family>>,
            CodecConformance<Response<mmr::Family, u64, sha256::Digest>>,
        }
    }
}
