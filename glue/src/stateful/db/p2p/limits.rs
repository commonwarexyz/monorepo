//! Size limits for the payloads the sync [`Actor`](super::Actor) sends.

use commonware_cryptography::Digest;
use commonware_p2p::Footprint;
use commonware_resolver::p2p::max_message_size;
use commonware_storage::{
    merkle::Family,
    qmdb::sync::{Request, max_response_size},
};
use commonware_utils::Widen;
use std::num::NonZeroU64;

/// Largest payloads the sync [`Actor`](super::Actor) sends, as
/// [message sizes](super#message-sizes) draws them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest resolver request or response, with its resolver framing.
    message: usize,
}

impl Limits {
    /// Returns the limits for an actor serving operations of at most `op` encoded bytes each, with
    /// [`Config::max_serve_ops`](super::Config::max_serve_ops) set to `max_ops`.
    ///
    /// # Panics
    ///
    /// Panics if `max_ops` exceeds `u32::MAX`, if the widest sync response exceeds the
    /// `u32::MAX` bytes a resolver response carries, or if a bound overflows `usize`.
    pub fn new<F: Family, D: Digest>(max_ops: NonZeroU64, op: usize) -> Self {
        // A response carries a proof with its operations, or a boundary operation with its pinned
        // nodes, as the resolver's value. A request carries a sync request as its key.
        let max_ops: usize = u32::try_from(max_ops.get())
            .map(Widen::widen)
            .expect("operations per request must fit in u32");
        let response =
            max_response_size::<F, D>(max_ops, op).expect("response size must fit in usize");
        let message = max_message_size::<Request<F>>(response)
            .expect("sync response must fit in a resolver response");
        Self { message }
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode, FixedSize, MaxEncodeSize};
    use commonware_cryptography::{Hasher as _, Sha256, sha256};
    use commonware_resolver::p2p::{MAX_RESPONSE_OVERHEAD, REQUEST_OVERHEAD};
    use commonware_storage::{
        merkle::{Location, MAX_PINNED_NODES, MAX_PROOF_DIGESTS_PER_ELEMENT},
        mmr::{self, Proof},
        qmdb::{any::unordered::fixed, sync::Response},
    };
    use commonware_utils::NZU64;

    type Op = fixed::Operation<mmr::Family, sha256::Digest, sha256::Digest>;
    type TestResponse = Response<mmr::Family, Op, sha256::Digest>;

    #[test]
    fn widest_encodings() {
        // The widest operations response carries `max_ops` operations and the most proof digests
        // a peer decodes for them. The widest boundary response carries the widest
        // single-operation proof and the most pinned nodes. Both decode, and the larger one plus
        // its resolver framing is exactly the footprint.
        let digest = Sha256::hash(&[b"digest"]);
        let proof = |count: usize| Proof {
            leaves: mmr::Family::MAX_LEAVES,
            inactive_peaks: usize::MAX,
            digests: vec![digest; count],
        };
        for max_ops in [1usize, 2, 16] {
            let operations = TestResponse::Operations {
                proof: proof(max_ops * MAX_PROOF_DIGESTS_PER_ELEMENT),
                operations: vec![Op::Delete(digest); max_ops],
            }
            .encode();
            let boundary = TestResponse::Boundary {
                proof: proof(MAX_PROOF_DIGESTS_PER_ELEMENT),
                op: Op::Delete(digest),
                pinned_nodes: vec![digest; MAX_PINNED_NODES],
            }
            .encode();
            assert!(TestResponse::decode_cfg(operations.clone(), &(max_ops, ())).is_ok());
            assert!(TestResponse::decode_cfg(boundary.clone(), &(max_ops, ())).is_ok());

            let limits = Limits::new::<mmr::Family, sha256::Digest>(
                NonZeroU64::new(Widen::widen(max_ops)).unwrap(),
                Op::SIZE,
            );
            assert_eq!(
                operations.len().max(boundary.len()) + MAX_RESPONSE_OVERHEAD,
                limits.footprint()
            );

            // The widest request with its resolver framing is smaller than the footprint.
            let request = Request::<mmr::Family>::Operations {
                size: mmr::Family::MAX_LEAVES,
                start: Location::new(*mmr::Family::MAX_LEAVES - 1),
                max_ops: NonZeroU64::MAX,
            };
            assert_eq!(
                request.encode().len(),
                Request::<mmr::Family>::MAX_ENCODE_SIZE
            );
            assert!(request.encode().len() + REQUEST_OVERHEAD < limits.footprint());
        }
    }

    #[test]
    #[should_panic(expected = "operations per request must fit in u32")]
    fn too_many_operations() {
        Limits::new::<mmr::Family, sha256::Digest>(NZU64!(1 << 32), Op::SIZE);
    }

    #[test]
    #[should_panic(expected = "response size must fit in usize")]
    fn response_overflow() {
        Limits::new::<mmr::Family, sha256::Digest>(NZU64!(2), usize::MAX);
    }
}
