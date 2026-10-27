//! Size limits for the payloads the DKG probe sends.

use super::wire::Message;
use commonware_consensus::{marshal::core::Variant, simplex::scheme::Scheme};
use commonware_p2p::Footprint;

/// Largest payloads the probe [`Actor`](super::Actor) sends, as
/// [message sizes](super#message-sizes) draws them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest request or response.
    message: usize,
}

impl Limits {
    /// Returns the limits for application blocks of at most `block` encoded bytes under `V` and
    /// committees of at most `participants` under `S`.
    ///
    /// # Panics
    ///
    /// Panics if `S` cannot bound certificates for a committee of `participants` or a bound
    /// overflows `usize`.
    pub fn new<V: Variant, S: Scheme<V::Commitment>>(participants: usize, block: usize) -> Self {
        let message = Message::<S, V>::max_encode_size(participants, block).expect(
            "scheme must bound certificates for participants and probe size must fit in usize",
        );
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
    use commonware_utils::{Widen, non_empty, test_rng};

    /// Signing namespace for the certificates these tests assemble.
    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_PROBE_LIMITS";

    type V = mocks::TestMarshalVariant;
    type S = ed25519::Scheme;

    /// Builds every message for a committee of `participants` with each varint at its widest,
    /// asserts that the widest encodes to exactly the footprint, and returns the sizes of a
    /// finalization response and a block response.
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

        // The limits are built for the block the response carries.
        let context = mocks::TestContext {
            round,
            leader: fixture.participants[0].clone(),
            parent: (View::new(u64::MAX - 1), digest),
        };
        let block =
            mocks::TestBlock::new::<Sha256>(context, digest, Height::new(u64::MAX), u64::MAX);
        let limits = Limits::new::<V, S>(Widen::widen(participants), block.encode_size());

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
        assert_eq!(sizes.into_iter().max(), Some(limits.footprint()));
        let [_, finalization, _, block, _, _] = sizes;
        (finalization, block)
    }

    #[test]
    fn widest_encodings() {
        // A committee of 1 has a finalization response narrower than the block response, and
        // larger committees a wider one, so each sets the footprint. Committees of 127 and 128 sit
        // on either side of the one-byte varint limit on a certificate's signature count.
        for participants in [1, 4, 127, 128] {
            let (finalization, block) = check(participants);
            assert_eq!(finalization < block, participants == 1);
        }
    }

    #[test]
    #[should_panic(expected = "scheme must bound certificates for participants")]
    fn unbounded_certificate() {
        Limits::new::<V, S>(Widen::<usize>::widen(u32::MAX) + 1, 0);
    }

    #[test]
    #[should_panic(expected = "probe size must fit in usize")]
    fn block_overflow() {
        Limits::new::<V, S>(4, usize::MAX);
    }
}
