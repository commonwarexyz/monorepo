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

/// Largest payloads marshal sends for blocks up to a target size, as a [`Footprint`] to fold
/// into the backfill network's [message size](crate::marshal#message-sizes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest backfill response, with resolver framing.
    response: usize,

    /// Largest buffer payload for the committees these limits cover, with room for a subchannel
    /// prefix.
    buffer: usize,
}

impl Limits {
    /// Returns limits for application blocks of at most `block` encoded bytes and committees of
    /// at most `participants` under `S`.
    ///
    /// Marshal admits every such block when its backfill sender's limit covers these limits'
    /// [footprint](Footprint::footprint), `participants` is its
    /// [`max_participants`](crate::marshal::Config::max_participants), and its buffer's own
    /// limit, if any, admits the block.
    ///
    /// # Panics
    ///
    /// Panics if `S` cannot bound certificates for a committee of `participants`, if `V` cannot
    /// disseminate the block to every committee of at most `participants` (coding requires
    /// `participants >= 4` and a scheme that encodes the block for every committee of 4 to
    /// `participants` members), or if a bound overflows `usize`.
    pub fn new<V: Variant, S: Verifier>(participants: usize, block: usize) -> Self {
        // Convert the application block bound to the variant's encoded block bound.
        let block = V::block_size(block).expect("encoded block size must fit in usize");

        // The largest response pairs a block with a notarization. A finalized response pairs the
        // application block with a finalization, and a block response carries no certificate.
        let certificate = S::certificate_max_size(participants)
            .expect("scheme must bound certificates for participants");
        let response = notarization::<V::Commitment>(certificate)
            .and_then(|size| size.checked_add(block))
            .and_then(|size| size.checked_add(Widen::widen(MAX_MESSAGE_OVERHEAD)))
            .expect("response size must fit in usize");

        // The buffer may run on a subchannel of the backfill network, so its payload leaves room
        // for the widest prefix.
        let buffer = V::buffer_size(participants, block)
            .expect("variant must disseminate the block to every committee of at most participants")
            .checked_add(MAX_U64_VARINT_SIZE)
            .expect("buffer payload size must fit in usize");

        Self { response, buffer }
    }
}

impl Footprint for Limits {
    fn footprint(&self) -> usize {
        self.response.max(self.buffer)
    }
}

/// Returns the largest encoded [`Variant::Block`] whose notarized response fits `value` bytes and
/// whose buffer payload, with a subchannel prefix, fits the backfill sender's limit of `value`
/// plus resolver framing, for committees of at most `participants` under `S`.
///
/// # Panics
///
/// Panics if `S` cannot bound certificates for a committee of `participants`, if `value` cannot
/// carry the widest notarization, if `V` cannot disseminate blocks to every committee of at most
/// `participants`, or if the backfill sender cannot carry an empty block's buffer payload.
pub(crate) fn bound<V: Variant, S: Verifier>(value: usize, participants: usize) -> usize {
    // `response` is the largest block whose notarized response fits the value.
    let certificate = S::certificate_max_size(participants)
        .expect("scheme must bound certificates for max_participants");
    let response = notarization::<V::Commitment>(certificate)
        .and_then(|notarization| value.checked_sub(notarization))
        .expect("backfill value must carry a notarization for max_participants");

    // The backfill sender's limit is the value plus resolver framing, saturating for a resolver
    // that carries values of any size. A buffer on the same network can send at least that limit
    // less the widest subchannel prefix.
    let limit = value.saturating_add(Widen::widen(MAX_MESSAGE_OVERHEAD));
    let payload = |block| {
        V::buffer_size(participants, block).and_then(|size| size.checked_add(MAX_U64_VARINT_SIZE))
    };

    // An empty block must fit, since the search below starts from it.
    let empty = payload(0)
        .expect("variant must disseminate blocks to every committee of at most max_participants");
    assert!(
        empty <= limit,
        "backfill sender must carry an empty block's buffer payload for max_participants"
    );

    // Buffer payloads never shrink as blocks grow, so binary search up to `response` for the
    // largest block whose payload fits.
    let fits = |block| payload(block).is_some_and(|size| size <= limit);
    let (mut low, mut high) = (0, response);
    while low < high {
        let mid = high - (high - low) / 2;
        if fits(mid) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
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
                block::{EmptyBlock, encode_block},
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

    /// Checks that a backfill sender sized by [`Limits`] yields a bound of exactly the target
    /// block, and that real notarizations and finalizations for that block fit the response
    /// limit, filling it at the widest.
    fn check_encoding<V: Variant, S: Scheme<V::Commitment>>(fixture: Fixture<S>, block: usize) {
        let schemes = fixture.schemes;
        let participants = schemes.len();
        let certificate_max_size = S::certificate_max_size(participants).unwrap();
        let scoped = Scoped::verifier(Arc::new(fixture.verifier));

        // A scheme and its scoped verifier yield the same limits and bound, and the bound round
        // trips to the target block.
        let limits = Limits::new::<V, S>(participants, block);
        assert_eq!(Limits::new::<V, Scoped<S>>(participants, block), limits);
        let overhead: usize = Widen::widen(MAX_MESSAGE_OVERHEAD);
        let value = limits.footprint() - overhead;
        assert_eq!(
            bound::<V, Scoped<S>>(value, participants),
            bound::<V, S>(value, participants)
        );
        let bound = bound::<V, S>(value, participants);
        assert_eq!(Some(bound), V::block_size(block));

        // A response adds the block and resolver framing to a notarization or finalization.
        // Certificates for views around the one-byte varint boundary and the largest view, from a
        // quorum or every signer, fit the scheme's bound and decode. Each response fits the limit,
        // and the largest view with every signer fills it exactly.
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
    #[should_panic(expected = "scheme must bound certificates for max_participants")]
    fn bound_unbounded_certificate() {
        let participants = Widen::<usize>::widen(u32::MAX) + 1;
        bound::<StandardVariant, ed25519::Scheme>(usize::MAX, participants);
    }

    #[test]
    #[should_panic(expected = "backfill value must carry a notarization for max_participants")]
    fn bound_below_notarization() {
        // A value that carries exactly the widest notarization admits only an empty block, and
        // one byte less panics.
        let certificate = ed25519::Scheme::certificate_max_size(4).unwrap();
        let notarization = notarization::<Sha256>(certificate).unwrap();
        assert_eq!(
            bound::<StandardVariant, ed25519::Scheme>(notarization, 4),
            0
        );
        bound::<StandardVariant, ed25519::Scheme>(notarization - 1, 4);
    }

    #[test]
    #[should_panic(
        expected = "variant must disseminate blocks to every committee of at most max_participants"
    )]
    fn bound_unsupported_participants() {
        bound::<CodingVariant, ed25519::Scheme>(1024 * 1024, 3);
    }

    #[test]
    fn standard_limits() {
        let limits = Limits::new::<StandardVariant, ed25519::Scheme>(4, 1000);
        let empty = Limits::new::<StandardVariant, ed25519::Scheme>(4, 0);
        assert_eq!(limits.response, empty.response + 1000);
        assert_eq!(limits.buffer, 1000 + MAX_U64_VARINT_SIZE);
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
    #[should_panic(expected = "response size must fit in usize")]
    fn response_overflow() {
        let empty = Limits::new::<StandardVariant, ed25519::Scheme>(4, 0);
        let largest = usize::MAX - empty.response;
        Limits::new::<StandardVariant, ed25519::Scheme>(4, largest + 1);
    }

    #[test]
    #[should_panic(expected = "response size must fit in usize")]
    fn block_overflow() {
        Limits::new::<StandardVariant, ed25519::Scheme>(4, usize::MAX);
    }

    #[test]
    #[should_panic(expected = "encoded block size must fit in usize")]
    fn coding_block_overflow() {
        Limits::new::<CodingVariant, ed25519::Scheme>(4, usize::MAX);
    }

    #[test]
    #[should_panic(expected = "scheme must bound certificates for participants")]
    fn unbounded_certificate() {
        let participants = Widen::<usize>::widen(u32::MAX) + 1;
        Limits::new::<StandardVariant, ed25519::Scheme>(participants, 0);
    }

    #[test]
    #[should_panic(
        expected = "variant must disseminate the block to every committee of at most participants"
    )]
    fn coding_too_few_participants() {
        Limits::new::<CodingVariant, ed25519::Scheme>(3, 100);
    }

    #[test]
    #[should_panic(
        expected = "variant must disseminate the block to every committee of at most participants"
    )]
    fn coding_unsupported_participants() {
        // One member more than the largest committee the Reed-Solomon coder supports.
        Limits::new::<CodingVariant, ed25519::Scheme>(49_154, 100);
    }

    #[test]
    fn coding_supported_participants() {
        // The largest committee the Reed-Solomon coder supports.
        let limits = Limits::new::<CodingVariant, ed25519::Scheme>(49_153, 100);
        assert!(limits.buffer > 0);
    }

    /// Returns the largest encoded shard over every index and every committee of 4 to
    /// `participants` members, and the smallest committee size that produces it.
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
            // what `block_size` reports.
            let config = coding_config_for_participants(n);
            let coded = encode_block::<CodingB, RS, Sha256Hasher>(block.clone(), config);
            let data = coded.encode();
            assert_eq!(
                Some(data.len()),
                CodingVariant::block_size(block.encode_size())
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
            let limits =
                Limits::new::<CodingVariant, ed25519::Scheme>(usize::from(participants), block);
            let widest = widest_shard(participants, block + CodingConfig::SIZE);
            assert_eq!(widest, (limits.buffer - MAX_U64_VARINT_SIZE, n));
        }
    }

    #[test]
    fn coding_bound_fits_shards() {
        type S = bls12381_threshold::standard::Scheme<PublicKey, MinSig>;

        // With a small certificate and block, the widest shard sets the footprint.
        for (participants, block) in [(33, 100), (100, 100)] {
            let limits = Limits::new::<CodingVariant, S>(usize::from(participants), block);
            let overhead: usize = Widen::widen(MAX_MESSAGE_OVERHEAD);
            let value = limits.footprint() - overhead;
            let bound = bound::<CodingVariant, S>(value, usize::from(participants));

            // The bound admits the target block, and the shard condition holds it below the
            // largest block a response carries.
            let certificate = S::certificate_max_size(usize::from(participants)).unwrap();
            let notarization =
                notarization::<<CodingVariant as Variant>::Commitment>(certificate).unwrap();
            let response = value - notarization;
            assert!(bound >= CodingVariant::block_size(block).unwrap());
            assert!(bound < response);

            // Every shard of the largest admitted block, with a subchannel prefix, fits the
            // backfill sender, and a block one byte larger has a shard that does not.
            let (widest, _) = widest_shard(participants, bound);
            assert!(widest + MAX_U64_VARINT_SIZE <= limits.footprint());
            let (widest, _) = widest_shard(participants, bound + 1);
            assert!(widest + MAX_U64_VARINT_SIZE > limits.footprint());
        }
    }
}
