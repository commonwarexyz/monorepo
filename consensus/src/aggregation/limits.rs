//! Size limits for the messages [aggregation](super) sends.

use super::scheme::Scheme;
use commonware_codec::{
    FixedSize, Footprint,
    varint::{MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE},
};
use commonware_cryptography::Digest;

/// Largest payload aggregation sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    ack: usize,
}

impl Limits {
    /// Returns the limits under `S` with item digest `D`.
    ///
    /// # Panics
    ///
    /// Panics if the bound overflows `usize`.
    pub fn new<S: Scheme<D>, D: Digest>() -> Self {
        // A tip ack is a tip, an item (height and digest), an epoch, and an attestation (signer
        // and signature).
        let ack = D::SIZE
            .checked_add(3 * MAX_U64_VARINT_SIZE + MAX_U32_VARINT_SIZE)
            .and_then(|size| size.checked_add(S::Signature::SIZE))
            .expect("ack size must fit in usize");
        Self { ack }
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        self.ack
    }
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
        let limits = Limits::new::<S, Sha256Digest>();

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
        assert_eq!(ack.encode().len(), limits.footprint());
    }

    #[test]
    fn test_limits() {
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
