//! Size limits for the payloads the probe sends.

use super::wire::Message;
use commonware_consensus::marshal::core::Variant;
use commonware_cryptography::certificate::Scheme;

/// Returns the largest payload the [`Probe`](super::Probe) sends for committees of at most
/// `participants` under `S` with the commitment of `V`: the widest request or response.
pub fn max_payload_size<V: Variant, S: Scheme>(participants: usize) -> usize {
    Message::<S, V>::max_encode_size(participants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::tests::mocks::TestVariant;
    use commonware_codec::Encode;
    use commonware_consensus::{
        simplex::{
            scheme::ed25519,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Hasher, sha256::Sha256};
    use commonware_parallel::Sequential;
    use commonware_utils::{Widen, non_empty, test_rng};

    /// Signing namespace for the certificates these tests assemble.
    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_STATEFUL_PROBE_LIMITS";

    type V = TestVariant;
    type S = ed25519::Scheme;

    /// Asserts that the widest message for a committee of `participants` encodes to exactly the
    /// largest payload.
    fn check(participants: u32) {
        let fixture = ed25519::fixture(&mut test_rng(), NAMESPACE, participants);
        let bound = max_payload_size::<V, S>(Widen::widen(participants));

        // A finalization with every varint at its widest and every signer.
        let proposal = Proposal::new(
            Round::new(Epoch::new(u64::MAX), View::new(u64::MAX)),
            View::new(u64::MAX - 1),
            Sha256::hash(&[b"block"]),
        );
        let finalizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_finalizes(&fixture.schemes[0], non_empty![@&finalizes], &Sequential)
                .unwrap();

        // The wider of a request and that response encodes to exactly the largest payload.
        let messages = [Message::<S, V>::Request, Message::Response(finalization)];
        let sizes = messages.map(|message| message.encode().len());
        assert_eq!(sizes.into_iter().max(), Some(bound));
    }

    #[test]
    fn widest_encodings() {
        // Committees of 127 and 128 sit on either side of the one-byte varint limit on a
        // certificate's signature count.
        for participants in [1, 4, 127, 128] {
            check(participants);
        }
    }

    #[test]
    #[should_panic(expected = "len must fit the u32 length prefix")]
    fn unbounded_certificate() {
        max_payload_size::<V, S>(Widen::<usize>::widen(u32::MAX) + 1);
    }
}
