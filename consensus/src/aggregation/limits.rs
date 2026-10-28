//! Size limits for the payloads [aggregation](super) sends.

use super::{scheme::Scheme, types::TipAck};
use commonware_codec::MaxEncodeSize;
use commonware_cryptography::Digest;

/// Returns the largest payload aggregation sends under `S` with item digest `D`: a tip ack with
/// every varint at its widest.
pub const fn max_payload_size<S: Scheme<D>, D: Digest>() -> usize {
    TipAck::<S, D>::MAX_ENCODE_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregation::{
            scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1},
            types::{Ack, Item, TipAck},
        },
        types::{Epoch, Height, Participant},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::{Attestation, mocks::Fixture},
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng;

    /// Signing namespace for the acks these tests sign.
    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_AGGREGATION_LIMITS";

    /// Asserts that the widest tip ack encodes to exactly its limit.
    fn check<S: Scheme<Sha256Digest>>(fixture: Fixture<S>) {
        let bound = max_payload_size::<S, Sha256Digest>();

        // Widen every varint.
        let item = Item {
            height: Height::new(u64::MAX),
            digest: Sha256Digest::random(test_rng()),
        };
        let ack = Ack::sign(&fixture.schemes[0], Epoch::new(u64::MAX), item).unwrap();
        let ack = TipAck {
            tip: Height::new(u64::MAX),
            ack: Ack {
                attestation: Attestation {
                    signer: Participant::new(u32::MAX),
                    signature: ack.attestation.signature.clone(),
                },
                ..ack
            },
        };
        assert_eq!(ack.encode().len(), bound);
    }

    #[test]
    fn widest_encodings() {
        check(ed25519::fixture(&mut test_rng(), NAMESPACE, 4));
        check(secp256r1::fixture(&mut test_rng(), NAMESPACE, 4));
        check(bls12381_multisig::fixture::<MinPk, _>(
            &mut test_rng(),
            NAMESPACE,
            4,
        ));
        check(bls12381_multisig::fixture::<MinSig, _>(
            &mut test_rng(),
            NAMESPACE,
            4,
        ));
        check(bls12381_threshold::fixture::<MinPk, _>(
            &mut test_rng(),
            NAMESPACE,
            4,
        ));
        check(bls12381_threshold::fixture::<MinSig, _>(
            &mut test_rng(),
            NAMESPACE,
            4,
        ));
    }
}
