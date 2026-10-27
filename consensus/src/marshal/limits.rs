//! Size limits for the payloads marshal sends.

use crate::{
    BoundedBlock,
    marshal::{core::Variant, resolver::handler::Key},
    simplex::types::{Finalization, Notarization},
};
use commonware_codec::Read;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Footprint;
use commonware_resolver::p2p::max_message_size;

/// Largest payloads marshal sends, as [message sizes](super#message-sizes) draws them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest backfill request or response, with resolver framing.
    backfill: usize,
    /// Largest buffer payload for the committees these limits cover.
    buffer: usize,
}

impl Limits {
    /// Returns the limits for the blocks `block_codec_config` decodes and committees of at most
    /// `participants` under `S`.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `block_codec_config` admits blocks of unbounded size
    /// - `S` cannot bound certificates for a committee of `participants`
    /// - `V` cannot disseminate the block to every committee of at most `participants` (under
    ///   coding, that needs `participants >= 4` and a scheme that encodes the block for every
    ///   committee of 4 to `participants` members)
    /// - the widest backfill value exceeds the `u32::MAX` bytes a resolver response carries
    /// - a size overflows `usize`
    pub fn new<V: Variant, S: Scheme>(
        participants: usize,
        block_codec_config: &<V::ApplicationBlock as Read>::Cfg,
    ) -> Self
    where
        V::ApplicationBlock: BoundedBlock,
    {
        // Convert the largest application block the configuration decodes to the encoded size of
        // the block marshal holds.
        let application = V::ApplicationBlock::max_encode_size(block_codec_config)
            .expect("block codec config must bound the block");
        let block = V::max_block_size(application).expect("encoded block size must fit in usize");

        // A response carries the block alone, a notarization with the block, or a finalization
        // with the application block. `max_message_size` covers the widest of these and a request
        // for a key, each with its resolver framing.
        let certificates = "scheme must bound certificates for participants";
        let notarized = Notarization::<S, V::Commitment>::max_encode_size(participants)
            .expect(certificates)
            .checked_add(block);
        let finalized = Finalization::<S, V::Commitment>::max_encode_size(participants)
            .expect(certificates)
            .checked_add(application);
        let value = [Some(block), notarized, finalized]
            .into_iter()
            .try_fold(0, |widest, size| size.map(|size| widest.max(size)))
            .expect("backfill size must fit in usize");
        let backfill = max_message_size::<Key<V::Commitment>>(value)
            .expect("backfill value must fit in a resolver response");

        // The variant sizes its buffer's widest payload from the application block for every
        // committee of at most `participants`.
        let buffer = V::max_buffer_size(participants, application).expect(
            "variant must disseminate the block to every committee of at most participants",
        );

        Self { backfill, buffer }
    }

    /// Returns the largest backfill request or response, with its resolver framing.
    pub const fn backfill(&self) -> usize {
        self.backfill
    }

    /// Returns the largest payload the buffer sends.
    pub const fn buffer(&self) -> usize {
        self.buffer
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        self.backfill.max(self.buffer)
    }
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
                block::{SizedBlock, encode_block},
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
    use commonware_codec::{Decode, Encode, EncodeSize, FixedSize};
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

    /// Application block of both variants.
    type TestBlock = SizedBlock<RS, Sha256Hasher, PublicKey>;
    type StandardVariant = Standard<TestBlock>;
    type CodingVariant = Coding<TestBlock, RS, Sha256Hasher, PublicKey>;

    /// Checks that backfill requests and responses for application blocks of at most
    /// `application` encoded bytes fit the backfill limit, and that the widest notarized response
    /// fills it exactly.
    fn check_encoding<V: Variant<ApplicationBlock = TestBlock>, S: Scheme<V::Commitment>>(
        fixture: Fixture<S>,
        application: usize,
    ) {
        let schemes = fixture.schemes;
        let participants = schemes.len();
        let max_certificate_size = S::max_certificate_size(participants).unwrap();
        let scoped = Scoped::verifier(Arc::new(fixture.verifier));
        let limits = Limits::new::<V, S>(participants, &Some(application));
        let block = V::max_block_size(application).unwrap();

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
            assert!(key.encode().len() + REQUEST_OVERHEAD <= limits.backfill);
        }
        assert!(block + MAX_RESPONSE_OVERHEAD <= limits.backfill);

        // Certificates for views around the one-byte varint boundary and the largest view, from a
        // quorum or every signer, fit `max_certificate_size` and decode. A notarized response adds
        // the block to a notarization and a finalized response the application block to a
        // finalization. Each fits the limit, and the widest notarized response fills it exactly.
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
                assert!(notarized <= limits.backfill);
                assert!(finalized <= limits.backfill);
                if view == u64::MAX && count == schemes.len() {
                    assert_eq!(notarized, limits.backfill);
                }
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
        // block alone, so backfill sets the footprint.
        let limits = Limits::new::<StandardVariant, ed25519::Scheme>(4, &Some(1000));
        let empty = Limits::new::<StandardVariant, ed25519::Scheme>(4, &Some(0));
        assert_eq!(limits.backfill(), empty.backfill() + 1000);
        assert_eq!(limits.buffer(), 1000);
        assert_eq!(limits.footprint(), limits.backfill);
    }

    #[test]
    fn largest_block() {
        // A resolver response carries a value of at most `u32::MAX` bytes. The widest notarized
        // response for the largest block fills it exactly.
        let empty = Limits::new::<StandardVariant, ed25519::Scheme>(4, &Some(0));
        let widest: usize = Widen::widen(u32::MAX);
        let largest = widest - (empty.backfill - MAX_RESPONSE_OVERHEAD);
        let limits = Limits::new::<StandardVariant, ed25519::Scheme>(4, &Some(largest));
        assert_eq!(limits.backfill, widest + MAX_RESPONSE_OVERHEAD);
        assert_eq!(limits.footprint(), limits.backfill);
    }

    #[test]
    #[should_panic(expected = "backfill value must fit in a resolver response")]
    fn response_overflow() {
        // One byte more than the largest block pushes the widest notarized value past `u32::MAX`.
        let empty = Limits::new::<StandardVariant, ed25519::Scheme>(4, &Some(0));
        let widest: usize = Widen::widen(u32::MAX);
        let largest = widest - (empty.backfill - MAX_RESPONSE_OVERHEAD);
        Limits::new::<StandardVariant, ed25519::Scheme>(4, &Some(largest + 1));
    }

    #[test]
    #[should_panic(expected = "block codec config must bound the block")]
    fn unbounded_block() {
        Limits::new::<StandardVariant, ed25519::Scheme>(4, &None);
    }

    #[test]
    #[should_panic(expected = "backfill size must fit in usize")]
    fn block_overflow() {
        // A notarized response for a block of `usize::MAX` bytes overflows `usize`.
        Limits::new::<StandardVariant, ed25519::Scheme>(4, &Some(usize::MAX));
    }

    #[test]
    #[should_panic(expected = "encoded block size must fit in usize")]
    fn coding_block_overflow() {
        // Appending the coding configuration to a block of `usize::MAX` bytes overflows `usize`.
        Limits::new::<CodingVariant, ed25519::Scheme>(4, &Some(usize::MAX));
    }

    #[test]
    #[should_panic(expected = "scheme must bound certificates for participants")]
    fn unbounded_certificate() {
        // An ed25519 signer bitmap covers at most `u32::MAX` participants.
        let participants = Widen::<usize>::widen(u32::MAX) + 1;
        Limits::new::<StandardVariant, ed25519::Scheme>(participants, &Some(0));
    }

    #[test]
    #[should_panic(
        expected = "variant must disseminate the block to every committee of at most participants"
    )]
    fn coding_too_few_participants() {
        // Coding needs a committee of at least 4.
        Limits::new::<CodingVariant, ed25519::Scheme>(3, &Some(100));
    }

    #[test]
    #[should_panic(
        expected = "variant must disseminate the block to every committee of at most participants"
    )]
    fn coding_unsupported_participants() {
        // One member more than the largest committee the Reed-Solomon coder supports.
        Limits::new::<CodingVariant, ed25519::Scheme>(49_154, &Some(100));
    }

    #[test]
    fn coding_supported_participants() {
        // The largest committee the Reed-Solomon coder supports.
        let limits = Limits::new::<CodingVariant, ed25519::Scheme>(49_153, &Some(100));
        assert!(limits.buffer > 0);
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
            // A coded block encodes as the block followed by its configuration, so its size is
            // what `max_block_size` reports.
            let config = coding_config_for_participants(n);
            let coded = encode_block::<CodingB, RS, Sha256Hasher>(block.clone(), config);
            let data = coded.encode();
            assert_eq!(
                Some(data.len()),
                Coding::<CodingB, RS, Sha256Hasher, PublicKey>::max_block_size(block.encode_size())
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
        for (participants, block, n) in [(16, 64 * 1024, 5), (33, 100, 33)] {
            let limits = Limits::new::<CodingVariant, ed25519::Scheme>(
                usize::from(participants),
                &Some(block),
            );
            let widest = widest_shard(participants, block + CodingConfig::SIZE);
            assert_eq!(widest.0, limits.buffer());
            assert_eq!(widest.1, n);
        }
    }

    #[test]
    fn coding_footprint_covers_shards() {
        type S = bls12381_threshold::standard::Scheme<PublicKey, MinSig>;

        // With a small certificate and block, the widest shard exceeds the widest backfill message
        // and sets the footprint.
        for (participants, block) in [(33, 100), (100, 100)] {
            let limits = Limits::new::<CodingVariant, S>(usize::from(participants), &Some(block));
            let (widest, _) = widest_shard(participants, block + CodingConfig::SIZE);
            assert!(widest > limits.backfill());
            assert_eq!(limits.footprint(), widest);
        }
    }
}
