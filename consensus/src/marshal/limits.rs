//! Size limits for the payloads marshal sends.

use crate::{
    BoundedBlock,
    marshal::{core::Variant, resolver::handler::Key},
    simplex::types::{Finalization, Notarization},
};
use commonware_codec::Read;
use commonware_cryptography::certificate::Scheme;
use commonware_resolver::p2p::max_message_size;

/// Returns an upper bound on the backfill messages marshal sends, including their resolver
/// framing, for committees of at most `participants` members and application blocks of at most
/// `application` encoded bytes.
fn max_backfill_size<V: Variant, S: Scheme>(participants: u32, application: usize) -> usize {
    // A response carries the backfill block alone, a notarization with the backfill block, or a
    // finalization with the application block. `max_message_size` covers the widest of these and
    // a request for a key, each with its resolver framing.
    let block = V::max_backfill_block_size(application);
    let notarized = Notarization::<S, V::Commitment>::max_encode_size(participants) + block;
    let finalized = Finalization::<S, V::Commitment>::max_encode_size(participants) + application;
    max_message_size::<Key<V::Commitment>>(block.max(notarized).max(finalized))
}

/// Returns an upper bound on the payloads marshal sends for committees of at most `participants`
/// members and blocks decoded under `block_codec_config`: the larger of the backfill and buffer
/// bounds.
pub fn max_payload_size<V: Variant, S: Scheme>(
    participants: u32,
    block_codec_config: &<V::ApplicationBlock as Read>::Cfg,
) -> usize
where
    V::ApplicationBlock: BoundedBlock,
{
    let application = V::ApplicationBlock::max_encode_size(block_codec_config);
    max_backfill_size::<V, S>(participants, application)
        .max(V::max_buffer_payload_size(participants, application))
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
            mocks::{
                block::encode_block,
                harness::{CodingB, CodingCtx, default_leader, make_coding_block},
            },
            standard::Standard,
        },
        simplex::{
            scheme::{Scheme, bls12381_multisig, bls12381_threshold, ed25519, secp256r1},
            types::{Finalization, Notarization, Proposal, Subject},
        },
        types::{Epoch, Height, Round, View, coding::Commitment},
    };
    use commonware_codec::{Decode, Encode, EncodeSize, FixedSize, MaxEncodeSize};
    use commonware_coding::{Config as CodingConfig, ReedSolomon, Scheme as _};
    use commonware_cryptography::{
        Committable, Sha256 as Sha256Hasher,
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::{Scoped, Verifier as _, mocks::Fixture},
        ed25519::PublicKey,
        sha256::Digest as Sha256,
    };
    use commonware_math::algebra::Random as _;
    use commonware_parallel::Sequential;
    use commonware_resolver::p2p::{MAX_RESPONSE_OVERHEAD, REQUEST_OVERHEAD};
    use commonware_utils::{Widen, non_empty, ordered::Quorum, test_rng};
    use std::sync::Arc;

    /// Signing namespace for the certificates these tests assemble.
    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MARSHAL_LIMITS";

    type RS = ReedSolomon<Sha256Hasher>;

    /// Both variants over the coding harness block. Its context names its parent by commitment, so
    /// it is an application block of either variant.
    type StandardVariant = Standard<CodingB>;
    type CodingVariant = Coding<CodingB, RS, Sha256Hasher, PublicKey>;

    /// Checks backfill bounds and encodings for application blocks of at most `application` bytes.
    fn check_encoding<V: Variant, S: Scheme<V::Commitment>>(
        fixture: Fixture<S>,
        application: usize,
    ) {
        let schemes = fixture.schemes;
        let participants = u32::try_from(schemes.len()).unwrap();
        let max_certificate_size = S::max_certificate_size(participants);
        let scoped = Scoped::verifier(Arc::new(fixture.verifier));
        let backfill = max_backfill_size::<V, S>(participants, application);
        let block = V::max_backfill_block_size(application);

        // The limit is the widest notarized response: a proposal and a certificate at their
        // bounds, the backfill block, and the response framing.
        assert_eq!(
            backfill,
            Proposal::<V::Commitment>::MAX_ENCODE_SIZE
                + max_certificate_size
                + block
                + MAX_RESPONSE_OVERHEAD
        );

        // A request for each key at its widest and a block response fit the limit with their
        // resolver framing.
        let commitment = V::Commitment::random(test_rng());
        for key in [
            Key::Block(commitment),
            Key::Finalized {
                height: Height::new(u64::MAX),
            },
            Key::Notarized {
                round: Round::new(Epoch::new(u64::MAX), View::new(u64::MAX)),
            },
        ] {
            assert!(key.encode().len() + REQUEST_OVERHEAD <= backfill);
        }
        assert!(block + MAX_RESPONSE_OVERHEAD <= backfill);

        // Certificates for views around the one-byte varint boundary and the largest view, from a
        // quorum or every signer, fit `max_certificate_size` and decode. A notarized response adds
        // the backfill block to a notarization and a finalized response the application block to a
        // finalization. Each fits the limit.
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
                assert!(encoded.len() <= max_certificate_size);
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
                let notarized = notarization.encode().len() + block + MAX_RESPONSE_OVERHEAD;
                let finalized = finalization.encode().len() + application + MAX_RESPONSE_OVERHEAD;
                assert!(notarized <= backfill);
                assert!(finalized <= backfill);
            }
        }
    }

    #[test]
    fn fixed_certificate_overhead() {
        // Threshold certificates have one fixed size for any committee and signer count.
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
        // These certificates carry a signer bitmap sized by the committee, and ed25519 and
        // secp256r1 add one signature per signer.
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
        // Coding commitments are wider than digests, and a coded block adds its configuration.
        let mut rng = test_rng();
        check_encoding::<CodingVariant, _>(
            bls12381_threshold::vrf::fixture::<MinSig, _>(&mut rng, NAMESPACE, 4),
            1000,
        );
        for participants in [4, 128] {
            check_encoding::<CodingVariant, _>(
                ed25519::fixture(&mut rng, NAMESPACE, participants),
                1000,
            );
        }
    }

    #[test]
    fn standard_limits() {
        // Under standard, backfill grows byte for byte with the block and the buffer sends the
        // block alone, so the backfill bound is the payload bound for the block bound.
        let backfill = max_backfill_size::<StandardVariant, ed25519::Scheme>(4, 1000);
        let empty = max_backfill_size::<StandardVariant, ed25519::Scheme>(4, 0);
        assert_eq!(backfill, empty + 1000);
        assert_eq!(StandardVariant::max_buffer_payload_size(4, 1000), 1000);
        let application = CodingB::max_encode_size(&());
        assert_eq!(
            max_payload_size::<StandardVariant, ed25519::Scheme>(4, &()),
            max_backfill_size::<StandardVariant, ed25519::Scheme>(4, application)
        );
    }

    #[test]
    fn largest_block() {
        // The response-value bound can reach the resolver's `u32::MAX` byte limit.
        let empty = max_backfill_size::<StandardVariant, ed25519::Scheme>(4, 0);
        let widest: usize = Widen::widen(u32::MAX);
        let largest = widest - (empty - MAX_RESPONSE_OVERHEAD);
        let backfill = max_backfill_size::<StandardVariant, ed25519::Scheme>(4, largest);
        assert_eq!(backfill, widest + MAX_RESPONSE_OVERHEAD);
    }

    #[test]
    #[should_panic(expected = "value must fit the u32 length prefix")]
    fn response_overflow() {
        // One more block byte pushes the response-value bound past `u32::MAX`.
        let empty = max_backfill_size::<StandardVariant, ed25519::Scheme>(4, 0);
        let widest: usize = Widen::widen(u32::MAX);
        let largest = widest - (empty - MAX_RESPONSE_OVERHEAD);
        max_backfill_size::<StandardVariant, ed25519::Scheme>(4, largest + 1);
    }

    #[test]
    #[should_panic(expected = "committee must have at least 4 members")]
    fn coding_too_few_participants() {
        // Coding needs a committee of at least 4.
        CodingVariant::max_buffer_payload_size(3, 100);
    }

    #[test]
    #[should_panic(expected = "backend must support the shard counts")]
    fn coding_unsupported_participants() {
        // One member more than the largest committee the Reed-Solomon coder supports.
        CodingVariant::max_buffer_payload_size(49_154, 100);
    }

    #[test]
    fn coding_supported_participants() {
        // The largest committee the Reed-Solomon coder supports.
        assert!(CodingVariant::max_buffer_payload_size(49_153, 100) > 0);
    }

    /// Codes `data` bytes for every committee of 4 to `participants` members and returns the
    /// encoded size of the widest shard at any index, with the smallest committee size that
    /// produces it.
    fn widest_shard(participants: u16, data: usize) -> (usize, u16) {
        let data = vec![0xAB; data];
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

    /// Checks that `widest_shard` measures the shards a real coded block produces.
    #[test]
    fn coded_block_shards_match_encoded_data() {
        // The block's parent, context, and payload are arbitrary.
        let parent = Commitment::<CodingB, RS, Sha256Hasher>::from((
            Sha256::random(test_rng()),
            Sha256::random(test_rng()),
            Sha256::random(test_rng()),
            coding_config_for_participants(4),
        ));
        let context = CodingCtx {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: default_leader(),
            parent: (View::zero(), parent),
        };
        let block = make_coding_block(context, Sha256::random(test_rng()), Height::new(1), 7);
        for n in [4u16, 5, 33] {
            // A coded block encodes as the application block followed by its coding configuration,
            // so its size is what `max_backfill_block_size` reports.
            let config = coding_config_for_participants(n);
            let coded = encode_block::<CodingB, RS, Sha256Hasher>(block.clone(), config);
            let data = coded.encode();
            assert_eq!(
                data.len(),
                Coding::<CodingB, RS, Sha256Hasher, PublicKey>::max_backfill_block_size(
                    block.encode_size()
                )
            );

            // The same root proves the coder saw exactly the coded block's encoding, and each real
            // shard encodes to the size of the shard `widest_shard` builds from that data.
            let (root, shards) = RS::encode(&config, data.as_ref(), &Sequential).unwrap();
            assert_eq!(root, coded.commitment().root());
            for (index, shard) in shards.into_iter().enumerate() {
                let index = u16::try_from(index).unwrap();
                let real = coded.shard(index).expect("shard must be encoded");
                assert_eq!(
                    real.encode().len(),
                    Shard::new(coded.commitment(), index, shard).encode().len()
                );
            }
        }
    }

    #[test]
    fn coding_limits() {
        // Committees of 4 to 6 members split a block into 2 data shards, and 5 or 6 members need
        // one more proof sibling than 4, so a large block is first widest at 5. A small block is
        // widest where the proof is deepest, and among 4 to 33 members only 33 needs 6 siblings.
        for (participants, block, n, expected) in [(16, 64 * 1024, 5, 32986), (33, 100, 33, 320)] {
            let buffer = CodingVariant::max_buffer_payload_size(u32::from(participants), block);
            let widest = widest_shard(participants, block + CodingConfig::SIZE);
            assert!(widest.0 <= buffer);
            assert_eq!(buffer, expected);
            assert_eq!(widest.1, n);
        }
    }

    #[test]
    fn coding_covers_shards() {
        type S = bls12381_threshold::standard::Scheme<PublicKey, MinSig>;

        // With a small certificate and block, the widest shard exceeds the backfill bound, so the
        // buffer bound sets the payload bound.
        for (participants, block, expected) in [(33, 100, 320), (100, 100, 348)] {
            let n = u32::from(participants);
            let (widest, _) = widest_shard(participants, block + CodingConfig::SIZE);
            assert!(widest > max_backfill_size::<CodingVariant, S>(n, block));
            let buffer = CodingVariant::max_buffer_payload_size(n, block);
            assert!(widest <= buffer);
            assert_eq!(buffer, expected);
        }

        // The payload bound for the blocks the codec decodes is the larger of the two bounds.
        let application = CodingB::max_encode_size(&());
        for n in [4, 33, 100] {
            assert_eq!(
                max_payload_size::<CodingVariant, S>(n, &()),
                max_backfill_size::<CodingVariant, S>(n, application)
                    .max(CodingVariant::max_buffer_payload_size(n, application))
            );
        }
    }
}
