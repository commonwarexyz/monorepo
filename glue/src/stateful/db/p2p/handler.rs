//! Internal handler types for resolver actor coordination.

use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Digest;
use commonware_resolver::{self as resolver, p2p::Producer};
use commonware_storage::mmr::{Location, Proof};
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
    Span,
};
use std::{fmt, num::NonZeroU64};

/// Maximum number of MMR peaks for a u64-indexed tree.
///
/// A Location is u64, so the tree has at most 62 peaks (popcount of 2^62 - 1).
const MAX_PEAKS: usize = 62;
/// Maximum proof digests per operation for MMR range proofs.
///
/// In the worst case (single operation in a maximal tree), proof size is 122:
/// 61 path siblings + 61 peak digests.
const MAX_PROOF_DIGESTS_PER_OPERATION: usize = (MAX_PEAKS - 1) * 2;

/// Request key sent through `resolver::p2p::Engine`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub(super) struct Request {
    /// Total operation count for proof context.
    pub op_count: Location,
    /// First operation location to fetch.
    pub start_loc: Location,
    /// Maximum number of operations to fetch.
    pub max_ops: NonZeroU64,
    /// Include pinned MMR nodes for `start_loc` when `true`.
    pub include_pinned_nodes: bool,
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Request(count={}, start={}, max={}, pinned={})",
            self.op_count, self.start_loc, self.max_ops, self.include_pinned_nodes,
        )
    }
}

impl Write for Request {
    fn write(&self, buf: &mut impl BufMut) {
        self.op_count.write(buf);
        self.start_loc.write(buf);
        self.max_ops.write(buf);
        self.include_pinned_nodes.write(buf);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        self.op_count.encode_size()
            + self.start_loc.encode_size()
            + self.max_ops.encode_size()
            + self.include_pinned_nodes.encode_size()
    }
}

impl Read for Request {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            op_count: Location::read(buf)?,
            start_loc: Location::read(buf)?,
            max_ops: NonZeroU64::read(buf)?,
            include_pinned_nodes: bool::read(buf)?,
        })
    }
}

impl Span for Request {}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Request {
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
/// Carries the MMR inclusion proof, the fetched operations, and
/// optionally the pinned MMR nodes at the requested start location.
/// Encoded by the producing peer and decoded by the consuming peer;
/// the actor converts this into a [`FetchResult`](commonware_storage::qmdb::sync::resolver::FetchResult)
/// before handing it to subscribers.
pub(super) struct Response<Op, D: Digest> {
    pub(super) proof: Proof<D>,
    pub(super) operations: Vec<Op>,
    pub(super) pinned_nodes: Option<Vec<D>>,
}

impl<Op: Write, D: Digest> Write for Response<Op, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.operations.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl<Op: EncodeSize, D: Digest> EncodeSize for Response<Op, D> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.operations.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl<Op: Read<Cfg = ()>, D: Digest> Read for Response<Op, D> {
    /// Maximum operations expected in this response, derived from the
    /// request's `max_ops` field.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_ops: &usize) -> Result<Self, CodecError> {
        let max_proof_digests = max_ops.saturating_mul(MAX_PROOF_DIGESTS_PER_OPERATION);
        let proof = Proof::<D>::read_cfg(buf, &max_proof_digests)?;
        let operations = Vec::<Op>::read_range(buf, ..=*max_ops)?;
        // Pinned nodes are the fold-prefix peaks at `start_loc`, independent of
        // `max_ops`. Bound them by the global MMR peak limit.
        let pinned_nodes = Option::<Vec<D>>::read_range(buf, ..=MAX_PEAKS)?;
        Ok(Self {
            proof,
            operations,
            pinned_nodes,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<Op, D: Digest> arbitrary::Arbitrary<'_> for Response<Op, D>
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
pub(super) enum EngineMessage {
    /// A peer delivered a response for a previously fetched key.
    /// The actor decodes the value, fans it out to waiting subscribers,
    /// and reports acceptance back through `response`.
    Deliver {
        key: Request,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    /// A peer requested data for `key`.
    /// The actor queries the local database and sends the encoded
    /// [`Response`] back through `response`.
    Produce {
        key: Request,
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
pub(super) struct Handler {
    sender: mpsc::Sender<EngineMessage>,
}

impl Handler {
    pub(super) const fn new(sender: mpsc::Sender<EngineMessage>) -> Self {
        Self { sender }
    }
}

impl resolver::Consumer for Handler {
    type Key = Request;
    type Value = Bytes;
    type Failure = ();

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

    async fn failed(&mut self, _: Self::Key, _: Self::Failure) {
        // The fetcher will automatically retry.
    }
}

impl Producer for Handler {
    type Key = Request;

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

    const TEST_MAX_OPS: usize = 10_000;

    #[test]
    fn response_codec_roundtrip() {
        let response = Response::<u64, sha256::Digest> {
            proof: Proof {
                leaves: commonware_storage::mmr::Location::new(10),
                digests: vec![sha256::Digest::from([7; 32])],
            },
            operations: vec![1, 2, 3],
            pinned_nodes: Some(vec![sha256::Digest::from([9; 32])]),
        };

        let encoded = response.encode();
        let decoded = Response::<u64, sha256::Digest>::decode_cfg(encoded, &TEST_MAX_OPS).unwrap();
        assert_eq!(decoded.operations, vec![1, 2, 3]);
        assert_eq!(
            decoded.proof.leaves,
            commonware_storage::mmr::Location::new(10)
        );
        assert_eq!(decoded.pinned_nodes.unwrap().len(), 1);
    }

    #[test]
    fn response_decode_rejects_invalid_pinned_flag() {
        let mut encoded = Response::<u64, sha256::Digest> {
            proof: Proof {
                leaves: commonware_storage::mmr::Location::new(10),
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

        let err = match Response::<u64, sha256::Digest>::decode_cfg(
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
        let response = Response::<u64, sha256::Digest> {
            proof: Proof {
                leaves: commonware_storage::mmr::Location::new(10),
                digests: vec![sha256::Digest::from([7; 32])],
            },
            operations: vec![1],
            pinned_nodes: Some(vec![sha256::Digest::from([9; 32]); 3]),
        };

        let encoded = response.encode();
        let decoded = Response::<u64, sha256::Digest>::decode_cfg(encoded, &max_ops).unwrap();
        assert_eq!(decoded.operations, vec![1]);
        assert_eq!(decoded.pinned_nodes.unwrap().len(), 3);
    }

    #[test]
    fn response_decode_allows_max_single_operation_proof() {
        let max_ops = 1usize;
        let response = Response::<u64, sha256::Digest> {
            proof: Proof {
                leaves: commonware_storage::mmr::Location::new(10),
                digests: vec![sha256::Digest::from([7; 32]); MAX_PROOF_DIGESTS_PER_OPERATION],
            },
            operations: vec![1],
            pinned_nodes: None,
        };

        let encoded = response.encode();
        let decoded = Response::<u64, sha256::Digest>::decode_cfg(encoded, &max_ops).unwrap();
        assert_eq!(decoded.operations, vec![1]);
        assert_eq!(decoded.proof.digests.len(), MAX_PROOF_DIGESTS_PER_OPERATION);
    }

    #[test]
    fn request_codec_roundtrip() {
        let req = Request {
            op_count: Location::new(128),
            start_loc: Location::new(64),
            max_ops: NonZeroU64::new(16).unwrap(),
            include_pinned_nodes: true,
        };
        let encoded = req.encode();
        let decoded = Request::decode(encoded).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn request_decode_rejects_invalid_pinned_flag() {
        let mut encoded = Request {
            op_count: Location::new(128),
            start_loc: Location::new(64),
            max_ops: NonZeroU64::new(16).unwrap(),
            include_pinned_nodes: true,
        }
        .encode()
        .to_vec();
        *encoded
            .last_mut()
            .expect("request encoding must include flag") = 2;

        let err = Request::decode(Bytes::from(encoded)).unwrap_err();
        assert!(matches!(err, CodecError::InvalidBool));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Request>,
            CodecConformance<Response<u64, sha256::Digest>>,
        }
    }
}
