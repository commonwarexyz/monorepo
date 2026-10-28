//! Size limits for the payloads the DKG probe sends.

use super::wire::Message;
use commonware_codec::Read;
use commonware_consensus::{BoundedBlock, marshal::core::Variant, simplex::scheme::Scheme};

/// Returns the largest payload the probe [`Actor`](super::Actor) sends for committees of at most
/// `participants` members and blocks decoded under `block_codec_config`.
pub fn max_payload_size<V: Variant, S: Scheme<V::Commitment>>(
    participants: u32,
    block_codec_config: &<V::ApplicationBlock as Read>::Cfg,
) -> usize
where
    V::ApplicationBlock: BoundedBlock,
{
    let application = V::ApplicationBlock::max_encode_size(block_codec_config);
    Message::<S, V>::max_encode_size(participants, application)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks;
    use commonware_codec::{Encode, EncodeSize};
    use commonware_consensus::{
        simplex::{
            scheme::ed25519,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{Digested, Digestible, Hasher, sha256::Sha256};
    use commonware_parallel::Sequential;
    use commonware_utils::{non_empty, test_rng};

    /// Signing namespace for the certificates these tests assemble.
    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_PROBE_LIMITS";

    type V = mocks::TestMarshalVariant;
    type S = ed25519::Scheme;

    /// Builds every message for a committee of `participants` with each varint at its widest,
    /// asserts that the widest encodes to exactly the size [`Message::max_encode_size`] reports
    /// for the block it carries, and returns the sizes of a finalization response and a block
    /// response.
    fn check(participants: u32) -> (usize, usize) {
        let fixture = ed25519::fixture(&mut test_rng(), NAMESPACE, participants);
        let epoch = Epoch::new(u64::MAX);
        let round = Round::new(epoch, View::new(u64::MAX));
        let digest = Sha256::hash(&[b"block"]);

        // A finalization with every varint at its widest and every signer.
        let proposal = Proposal::new(round, View::new(u64::MAX - 1), digest);
        let finalizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_finalizes(&fixture.schemes[0], non_empty![@&finalizes], &Sequential)
                .unwrap();

        // The bound is taken for the block the response carries.
        let context = mocks::TestContext {
            round,
            leader: fixture.participants[0].clone(),
            parent: (View::new(u64::MAX - 1), digest),
        };
        let block =
            mocks::TestBlock::new::<Sha256>(context, digest, Height::new(u64::MAX), u64::MAX);
        let bound = Message::<S, V>::max_encode_size(participants, block.encode_size());

        // The widest message kind encodes to exactly the bound.
        let messages = [
            Message::<S, V>::BoundaryRequest(epoch),
            Message::BoundaryResponse(finalization.clone()),
            Message::BlockRequest(epoch),
            Message::BlockResponse {
                epoch,
                block: Digested::precomputed(block.clone(), block.digest()),
            },
            Message::LatestRequest,
            Message::LatestResponse(finalization),
        ];
        let sizes = messages.map(|message| message.encode().len());
        assert_eq!(sizes.into_iter().max(), Some(bound));
        let [_, finalization, _, block, _, _] = sizes;
        (finalization, block)
    }

    #[test]
    fn widest_encodings() {
        // A committee of 1 has a finalization response narrower than the block response and larger
        // committees a wider one, so each response is the largest payload for some committee.
        // Committees of 127 and 128 sit on either side of the one-byte varint limit on a
        // certificate's signature count.
        for participants in [1, 4, 127, 128] {
            let (finalization, block) = check(participants);
            assert_eq!(finalization < block, participants == 1);
        }
    }
}
