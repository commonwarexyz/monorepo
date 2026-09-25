//! Size limits for the payloads the probe sends.

use super::wire::Message;
use commonware_consensus::simplex::marshal::core::Variant;
use commonware_cryptography::certificate::Scheme;

/// Returns an upper bound on the payloads the [`Probe`](super::Probe) sends for committees of at
/// most `participants` members.
pub fn max_payload_size<V: Variant, S: Scheme>(participants: u32) -> usize {
    Message::<S, V>::max_encode_size(participants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::tests::mocks::TestVariant;
    use commonware_codec::{Encode, EncodeSize};
    use commonware_consensus::{
        simplex::{
            scheme::ed25519,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Hasher, certificate::Verifier as _, sha256::Sha256};
    use commonware_parallel::Sequential;
    use commonware_utils::{non_empty, test_rng};

    /// Signing namespace for the certificates these tests assemble.
    const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_STATEFUL_PROBE_LIMITS";

    type V = TestVariant;
    type S = ed25519::Scheme;

    /// Checks the payload bound against the encoded response and its signature-list prefix.
    fn check(participants: u32) {
        let fixture = ed25519::fixture(&mut test_rng(), NAMESPACE, participants);
        let bound = max_payload_size::<V, S>(participants);

        // Use every signer and the widest round and parent view.
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
        let certificate_slack =
            S::max_certificate_size(participants) - finalization.certificate.encode_size();

        // The request is narrower than the response. The response falls short of the bound by the
        // unused width of its certificate's signature-list prefix.
        let messages = [Message::<S, V>::Request, Message::Response(finalization)];
        let [request, response] = messages.map(|message| message.encode().len());
        assert!(request < response);
        assert_eq!(response + certificate_slack, bound);
    }

    #[test]
    fn widest_encodings() {
        // Committees of 127 and 128 sit on either side of the one-byte varint limit on a
        // certificate's signature count.
        for participants in [1, 4, 127, 128] {
            check(participants);
        }
    }
}
