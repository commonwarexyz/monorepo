//! Size bounds for the blocks marshal admits and the payloads it sends.

use crate::marshal::core::Variant;
use commonware_codec::varint::MAX_U64_VARINT_SIZE;
use commonware_cryptography::{Digest, certificate::Verifier};
use commonware_p2p::Footprint;
use commonware_resolver::p2p::MAX_MESSAGE_OVERHEAD;
use commonware_utils::Widen;

/// Returns the largest encoded notarization or finalization with commitment `C` and a
/// certificate of at most `certificate` bytes: a proposal (round, parent view, and commitment)
/// and the certificate.
const fn notarization<C: Digest>(certificate: usize) -> Option<usize> {
    certificate.checked_add(3 * MAX_U64_VARINT_SIZE + C::SIZE)
}

/// Largest payloads marshal sends for a target block size. See
/// [message sizes](crate::marshal#message-sizes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    response: usize,
    buffer: usize,
}

impl Limits {
    /// Returns limits for committees of at most `participants` under `S`, where `block` is the
    /// largest encoded application block.
    ///
    /// Marshal admits `block` when its backfill sender carries these limits and `participants` is
    /// its [`max_participants`](crate::marshal::Config::max_participants).
    ///
    /// # Panics
    ///
    /// Panics if `S` cannot bound certificates for `participants` participants, if `V` cannot
    /// bound its buffer payload for `participants` (coding requires `participants >= 4` and a
    /// scheme that encodes the largest block for every committee of 4 to `participants` members),
    /// or if a bound overflows `usize`.
    pub fn new<V: Variant, S: Verifier>(participants: usize, block: usize) -> Self {
        // Convert the application block bound to the variant's encoded block bound
        let block = V::block_size(block).expect("block size overflow");

        // A notarized response is the largest: a block and a notarization. Finalized responses
        // carry the application block, and block responses carry no certificate.
        let certificate = S::certificate_max_size(participants)
            .expect("scheme cannot bound certificates for participants");
        let response = notarization::<V::Commitment>(certificate)
            .and_then(|size| size.checked_add(block))
            .and_then(|size| size.checked_add(Widen::widen(MAX_MESSAGE_OVERHEAD)))
            .expect("response size overflow");

        let buffer = V::buffer_size(participants, block)
            .expect("variant cannot carry blocks for participants");

        Self { response, buffer }
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        self.response.max(self.buffer)
    }
}

/// Returns the largest encoded [`Variant::Block`] whose notarized response fits a resolver value
/// of at most `value` bytes, for committees of at most `participants` under `S`.
///
/// # Panics
///
/// Panics if `S` cannot bound certificates for `participants` participants or if `value` cannot
/// carry the widest notarization.
pub(crate) fn bound<C: Digest, S: Verifier>(value: usize, participants: usize) -> usize {
    let certificate = S::certificate_max_size(participants)
        .expect("scheme cannot bound certificates for max_participants");
    notarization::<C>(certificate)
        .and_then(|notarization| value.checked_sub(notarization))
        .expect("backfill value cannot carry a notarization for max_participants")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{
            coding::{
                Coding,
                types::{Shard, coding_config_for_participants},
            },
            mocks::{block::EmptyBlock, harness::CodingB},
            standard::Standard,
        },
        simplex::{
            scheme::{Scheme, bls12381_multisig, bls12381_threshold, ed25519, secp256r1},
            types::{Finalization, Notarization, Proposal, Subject},
        },
        types::{Epoch, Round, View, coding::Commitment},
    };
    use commonware_codec::{Decode, Encode, FixedSize};
    use commonware_coding::{Config as CodingConfig, ReedSolomon, Scheme as _};
    use commonware_cryptography::{
        Sha256 as Sha256Hasher,
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::{Scoped, mocks::Fixture},
        ed25519::PublicKey,
        sha256::Digest as Sha256,
    };
    use commonware_math::algebra::Random as _;
    use commonware_parallel::Sequential;
    use commonware_utils::{non_empty, ordered::Quorum, test_rng};
    use std::sync::Arc;

    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MARSHAL_SIZING";

    type RS = ReedSolomon<Sha256Hasher>;
    type StandardVariant = Standard<EmptyBlock<Sha256Hasher>>;
    type CodingVariant = Coding<CodingB, RS, Sha256Hasher, PublicKey>;

    /// Asserts that a backfill sender sized by [`Limits`] admits exactly the target block, and
    /// that the block with the widest notarization or finalization fills the sender.
    fn check_encoding<V: Variant, S: Scheme<V::Commitment>>(fixture: Fixture<S>, block: usize) {
        let schemes = fixture.schemes;
        let participants = schemes.len();
        let limits = Limits::new::<V, S>(participants, block);
        assert_eq!(Limits::new::<V, Scoped<S>>(participants, block), limits);
        let certificate_max_size = S::certificate_max_size(participants).unwrap();
        let scoped = Scoped::verifier(Arc::new(fixture.verifier));

        // The derived bound round trips to the target block
        let overhead: usize = Widen::widen(MAX_MESSAGE_OVERHEAD);
        let value = limits.response - overhead;
        assert_eq!(
            bound::<V::Commitment, Scoped<S>>(value, participants),
            bound::<V::Commitment, S>(value, participants)
        );
        let bound = bound::<V::Commitment, S>(value, participants);
        assert_eq!(Some(bound), V::block_size(block));

        // A response adds a block and resolver framing to a notarization or finalization
        let extra = bound + overhead;
        for view in [1, 127, 128, u64::MAX] {
            let proposal = Proposal::new(
                Round::new(Epoch::new(view), View::new(view)),
                View::new(view - 1),
                V::Commitment::random(test_rng()),
            );
            for count in [
                Widen::widen(schemes[0].participants().quorum::<S::Faults>()),
                schemes.len(),
            ] {
                let attestations = schemes.iter().take(count).map(|scheme| {
                    scheme
                        .sign::<V::Commitment>(Subject::Notarize {
                            proposal: &proposal,
                        })
                        .unwrap()
                });
                let certificate = schemes[0]
                    .assemble(non_empty![@attestations], &Sequential)
                    .unwrap();
                let encoded = certificate.encode();
                assert!(encoded.len() <= certificate_max_size);
                assert!(
                    S::Certificate::decode_cfg(encoded, &scoped.certificate_codec_config()).is_ok()
                );
                let notarization = Notarization::<S, V::Commitment> {
                    proposal: proposal.clone(),
                    certificate: certificate.clone(),
                };
                let finalization = Finalization::<S, V::Commitment> {
                    proposal: proposal.clone(),
                    certificate,
                };
                for encoded in [notarization.encode(), finalization.encode()] {
                    assert!(extra + encoded.len() <= limits.response);
                    if view == u64::MAX && count == schemes.len() {
                        assert_eq!(extra + encoded.len(), limits.response);
                    }
                }
            }
        }
    }

    #[test]
    fn fixed_certificate_overhead() {
        let mut rng = test_rng();
        check_encoding::<StandardVariant, _>(
            bls12381_threshold::standard::fixture::<MinSig, _>(&mut rng, NAMESPACE, 4),
            0,
        );
        check_encoding::<StandardVariant, _>(
            bls12381_threshold::standard::fixture::<MinPk, _>(&mut rng, NAMESPACE, 4),
            1000,
        );
        check_encoding::<StandardVariant, _>(
            bls12381_threshold::vrf::fixture::<MinSig, _>(&mut rng, NAMESPACE, 4),
            0,
        );
        check_encoding::<StandardVariant, _>(
            bls12381_threshold::vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 4),
            1000,
        );
    }

    #[test]
    fn variable_certificate_overhead() {
        let mut rng = test_rng();
        for participants in [4, 128] {
            check_encoding::<StandardVariant, _>(
                ed25519::fixture(&mut rng, NAMESPACE, participants),
                1000,
            );
        }
        check_encoding::<StandardVariant, _>(secp256r1::fixture(&mut rng, NAMESPACE, 4), 0);
        check_encoding::<StandardVariant, _>(
            bls12381_multisig::fixture::<MinSig, _>(&mut rng, NAMESPACE, 4),
            0,
        );
        check_encoding::<StandardVariant, _>(
            bls12381_multisig::fixture::<MinPk, _>(&mut rng, NAMESPACE, 4),
            1000,
        );
    }

    #[test]
    fn coding_commitment_overhead() {
        check_encoding::<CodingVariant, _>(
            bls12381_threshold::vrf::fixture::<MinSig, _>(&mut test_rng(), NAMESPACE, 4),
            1000,
        );
    }

    #[test]
    #[should_panic(expected = "scheme cannot bound certificates for max_participants")]
    fn bound_unbounded_certificate() {
        let participants = Widen::<usize>::widen(u32::MAX) + 1;
        bound::<Sha256, ed25519::Scheme>(usize::MAX, participants);
    }

    #[test]
    #[should_panic(expected = "backfill value cannot carry a notarization for max_participants")]
    fn bound_below_notarization() {
        let certificate = ed25519::Scheme::certificate_max_size(4).unwrap();
        let notarization = notarization::<Sha256>(certificate).unwrap();
        assert_eq!(bound::<Sha256, ed25519::Scheme>(notarization, 4), 0);
        bound::<Sha256, ed25519::Scheme>(notarization - 1, 4);
    }

    #[test]
    fn standard_limits() {
        let limits = Limits::new::<StandardVariant, ed25519::Scheme>(4, 1000);
        let empty = Limits::new::<StandardVariant, ed25519::Scheme>(4, 0);
        assert_eq!(limits.response, empty.response + 1000);
        assert_eq!(limits.buffer, 1000);
        assert_eq!(limits.footprint(), limits.response);
    }

    #[test]
    fn largest_block() {
        let empty = Limits::new::<StandardVariant, ed25519::Scheme>(4, 0);
        let largest = usize::MAX - empty.response;
        let limits = Limits::new::<StandardVariant, ed25519::Scheme>(4, largest);
        assert_eq!(limits.response, usize::MAX);
        assert_eq!(limits.footprint(), usize::MAX);
    }

    #[test]
    #[should_panic(expected = "response size overflow")]
    fn response_overflow() {
        let empty = Limits::new::<StandardVariant, ed25519::Scheme>(4, 0);
        let largest = usize::MAX - empty.response;
        Limits::new::<StandardVariant, ed25519::Scheme>(4, largest + 1);
    }

    #[test]
    #[should_panic(expected = "response size overflow")]
    fn block_overflow() {
        Limits::new::<StandardVariant, ed25519::Scheme>(4, usize::MAX);
    }

    #[test]
    #[should_panic(expected = "block size overflow")]
    fn coding_block_overflow() {
        Limits::new::<CodingVariant, ed25519::Scheme>(4, usize::MAX);
    }

    #[test]
    #[should_panic(expected = "scheme cannot bound certificates for participants")]
    fn unbounded_certificate() {
        let participants = Widen::<usize>::widen(u32::MAX) + 1;
        Limits::new::<StandardVariant, ed25519::Scheme>(participants, 0);
    }

    #[test]
    #[should_panic(expected = "variant cannot carry blocks for participants")]
    fn coding_too_few_participants() {
        Limits::new::<CodingVariant, ed25519::Scheme>(3, 100);
    }

    #[test]
    #[should_panic(expected = "variant cannot carry blocks for participants")]
    fn coding_unsupported_participants() {
        Limits::new::<CodingVariant, ed25519::Scheme>(49_154, 100);
    }

    #[test]
    fn coding_supported_participants() {
        let limits = Limits::new::<CodingVariant, ed25519::Scheme>(49_153, 100);
        assert!(limits.buffer > 0);
    }

    /// Returns the largest encoded shard over every index and every committee of 4 to
    /// `participants` members, and the committee size that produces it.
    fn widest_shard(participants: u16, block: usize) -> (usize, u16) {
        let data = vec![0xAB; block];
        let mut widest = (0, 0);
        for n in 4..=participants {
            let config = coding_config_for_participants(n);
            let (root, shards) = RS::encode(&config, data.as_slice(), &Sequential).unwrap();
            let commitment = Commitment::<CodingB, RS, Sha256Hasher>::from((
                Sha256::random(test_rng()),
                root,
                Sha256::random(test_rng()),
                config,
            ));
            for (index, shard) in shards.into_iter().enumerate() {
                let index = u16::try_from(index).unwrap();
                let size = Shard::new(commitment, index, shard).encode().len();
                if size > widest.0 {
                    widest = (size, n);
                }
            }
        }
        widest
    }

    #[test]
    fn coding_limits() {
        // Committees of 4 to 6 split blocks into 2 shards, and 5 or 6 members need a deeper proof,
        // so large blocks are widest at 5. Small blocks are widest where proofs are deepest: of 4
        // to 33 members, only 33 needs 6 siblings.
        for (participants, block, n) in [(16, 64 * 1024, 5), (33, 100, 33)] {
            let limits =
                Limits::new::<CodingVariant, ed25519::Scheme>(usize::from(participants), block);
            let widest = widest_shard(participants, block + CodingConfig::SIZE);
            assert_eq!(widest, (limits.buffer, n));
        }
    }
}
