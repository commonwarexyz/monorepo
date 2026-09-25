//! Size limits for the payloads the DKG probe sends.

use super::wire::Message;
use commonware_codec::Read;
use commonware_consensus::{
    BoundedBlock,
    simplex::{marshal::core::Variant, scheme::Scheme},
};

/// Returns an upper bound on the payloads the probe [`Actor`](super::Actor) sends for committees
/// of at most `participants` members and blocks decoded under `block_codec_config`.
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
    use commonware_cryptography::{
        Digested, Digestible, Hasher, certificate::Verifier as _, sha256::Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{non_empty, test_rng};

    /// Signing namespace for the certificates these tests assemble.
    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_PROBE_LIMITS";

    type V = mocks::TestMarshalVariant;
    type S = ed25519::Scheme;

    /// Checks every message against the payload bound and returns the finalization and block
    /// response bounds.
    fn check(participants: u32) -> (usize, usize) {
        let fixture = ed25519::fixture(&mut test_rng(), NAMESPACE, participants);
        let epoch = Epoch::new(u64::MAX);
        let round = Round::new(epoch, View::new(u64::MAX));
        let digest = Sha256::hash(&[b"block"]);

        // Use every signer and the widest round and parent view.
        let proposal = Proposal::new(round, View::new(u64::MAX - 1), digest);
        let finalizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_finalizes(&fixture.schemes[0], non_empty![@&finalizes], &Sequential)
                .unwrap();
        let certificate_slack =
            S::max_certificate_size(participants) - finalization.certificate.encode_size();

        // The bound is taken for the block the response carries.
        let context = mocks::TestContext {
            round,
            leader: fixture.participants[0].clone(),
            parent: (View::new(u64::MAX - 1), digest),
        };
        let block =
            mocks::TestBlock::new::<Sha256>(context, digest, Height::new(u64::MAX), u64::MAX);
        let bound = Message::<S, V>::max_encode_size(participants, block.encode_size());

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
        let mut sizes = messages.map(|message| message.encode().len());
        assert!(sizes.iter().all(|&size| size <= bound));

        // The finalization responses fall short of their bound by the unused width of the
        // certificate's signature-list prefix. With it added, the widest message reaches the bound.
        sizes[1] += certificate_slack;
        sizes[5] += certificate_slack;
        assert_eq!(sizes.into_iter().max(), Some(bound));
        let [_, finalization, _, block, _, _] = sizes;
        (finalization, block)
    }

    #[test]
    fn widest_encodings() {
        // Each response sets the payload bound for some committee, since the finalization response
        // bound is narrower than the block response for a committee of 1 and wider for larger ones.
        // Committees of 127 and 128 sit on either side of the one-byte varint limit on a
        // certificate's signature count.
        for participants in [1, 4, 127, 128] {
            let (finalization, block) = check(participants);
            assert_eq!(finalization < block, participants == 1);
        }
    }
}
