//! Size limits for the payloads the sync [`Actor`](super::Actor) sends.

use commonware_cryptography::Digest;
use commonware_resolver::p2p::max_message_size;
use commonware_storage::{
    merkle::Family,
    qmdb::sync::{Request, max_response_size},
};
use commonware_utils::Widen;
use std::num::NonZeroU64;

/// Returns an upper bound on the payloads the sync [`Actor`](super::Actor) sends when its
/// [`Config::max_serve_ops`](super::Config::max_serve_ops) is `max_serve_ops` and each operation
/// encodes to at most `op` bytes.
///
/// # Panics
///
/// Panics if `max_serve_ops` exceeds `u32::MAX`.
pub fn max_payload_size<F: Family, D: Digest>(max_serve_ops: NonZeroU64, op: usize) -> usize {
    let max_ops: usize = u32::try_from(max_serve_ops.get())
        .map(Widen::widen)
        .expect("operations per request must fit in u32");

    // A response carries a proof with its operations, or a boundary operation with its pinned
    // nodes, as the resolver's value. A request carries a sync request as its key.
    let response = max_response_size::<F, D>(max_ops, op);
    max_message_size::<Request<F>>(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{
        Decode, Encode, EncodeSize, FixedSize, MaxEncodeSize, varint::MAX_U32_VARINT_SIZE,
    };
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
        // Every proof takes the largest leaf count and inactive peak count the codec decodes.
        let digest = Sha256::hash(&[b"digest"]);
        let proof = |count: usize| Proof {
            leaves: mmr::Family::MAX_LEAVES,
            inactive_peaks: usize::MAX,
            digests: vec![digest; count],
        };
        let location_slack =
            Location::<mmr::Family>::MAX_ENCODE_SIZE - mmr::Family::MAX_LEAVES.encode_size();
        for max_ops in [1usize, 2, 16] {
            // The widest operations response carries `max_ops` operations and the most proof
            // digests a peer decodes for them. The widest boundary response carries the widest
            // single-operation proof and the most pinned nodes. Both decode.
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

            // Each response falls short of its bound by the unused width of its proof's leaf count
            // and two length prefixes.
            let operations_slack = location_slack + 2 * MAX_U32_VARINT_SIZE
                - (max_ops * MAX_PROOF_DIGESTS_PER_ELEMENT).encode_size()
                - max_ops.encode_size();
            let boundary_slack = location_slack + 2 * MAX_U32_VARINT_SIZE
                - MAX_PROOF_DIGESTS_PER_ELEMENT.encode_size()
                - MAX_PINNED_NODES.encode_size();
            let bound = max_payload_size::<mmr::Family, sha256::Digest>(
                NonZeroU64::new(Widen::widen(max_ops)).unwrap(),
                Op::SIZE,
            );
            assert_eq!(
                (operations.len() + operations_slack).max(boundary.len() + boundary_slack)
                    + MAX_RESPONSE_OVERHEAD,
                bound
            );

            // The widest request falls short of its bound by the unused width of its two
            // locations, and it stays smaller than the payload bound.
            let size = mmr::Family::MAX_LEAVES;
            let start = Location::new(*size - 1);
            let request = Request::<mmr::Family>::Operations {
                size,
                start,
                max_ops: NonZeroU64::MAX,
            };
            assert_eq!(
                request.encode().len()
                    + (Location::<mmr::Family>::MAX_ENCODE_SIZE - size.encode_size())
                    + (Location::<mmr::Family>::MAX_ENCODE_SIZE - start.encode_size()),
                Request::<mmr::Family>::MAX_ENCODE_SIZE
            );
            assert!(request.encode().len() + REQUEST_OVERHEAD < bound);
        }
    }

    #[test]
    #[should_panic(expected = "operations per request must fit in u32")]
    fn too_many_operations() {
        max_payload_size::<mmr::Family, sha256::Digest>(NZU64!(1 << 32), Op::SIZE);
    }
}
