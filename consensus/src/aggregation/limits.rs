//! Size limits for the messages [aggregation](super) sends.

use super::scheme::Scheme;
use commonware_codec::{
    FixedSize,
    varint::{MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE},
};
use commonware_cryptography::Digest;
use commonware_p2p::Footprint;

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
        // and signature)
        let ack = D::SIZE
            .checked_add(3 * MAX_U64_VARINT_SIZE + MAX_U32_VARINT_SIZE)
            .and_then(|size| size.checked_add(S::Signature::SIZE))
            .expect("ack size overflow");
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
            scheme::ed25519,
            types::{Ack, Item, TipAck},
        },
        types::{Epoch, Height, Participant},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{certificate::Attestation, sha256::Digest as Sha256Digest};
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng;

    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_AGGREGATION_LIMITS";

    /// Asserts that the widest tip ack encodes to exactly its limit.
    #[test]
    fn test_limits() {
        let fixture = ed25519::fixture(&mut test_rng(), NAMESPACE, 4);
        let limits = Limits::new::<ed25519::Scheme, Sha256Digest>();

        // Widen every varint
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
}
