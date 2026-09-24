use crate::marshal::core::Variant;
use commonware_codec::{FixedSize, varint::MAX_U64_VARINT_SIZE};
use commonware_cryptography::certificate::Verifier;
use commonware_resolver::p2p::MAX_RESPONSE_OVERHEAD;

/// Returns the maximum size of a marshal recovery response beyond its block, in bytes.
///
/// The result covers the proposal over `V::Commitment`, the largest certificate `scheme`
/// accepts (see [`Verifier::certificate_max_size`]), and [`MAX_RESPONSE_OVERHEAD`] bytes of
/// resolver framing. A configuration is sufficient when the maximum encoded
/// [`Variant::Block`] size plus this overhead is at most the P2P message size limit. When
/// serving multiple epochs or committees, use the largest result across their verifiers.
///
/// Returns `None` if the verifier cannot bound certificate size or the overhead does not fit
/// in a `u32`.
///
/// # Examples
///
/// Bound the encoded block size for standard marshal:
///
/// ```
/// use commonware_consensus::{
///     Block,
///     marshal::{max_recovery_overhead, standard::Standard},
/// };
/// use commonware_cryptography::certificate::Verifier;
///
/// fn max_block_size<B: Block>(scheme: &impl Verifier, max_message_size: u32) -> Option<u32> {
///     let overhead = max_recovery_overhead::<Standard<B>>(scheme)?;
///     max_message_size.checked_sub(overhead)
/// }
/// ```
pub fn max_recovery_overhead<V: Variant>(scheme: &impl Verifier) -> Option<u32> {
    scheme
        .certificate_max_size()?
        .checked_add(V::Commitment::SIZE)?
        .checked_add(3 * MAX_U64_VARINT_SIZE)?
        .checked_add(MAX_RESPONSE_OVERHEAD as usize)?
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{
            coding::Coding,
            mocks::{block::EmptyBlock, harness::CodingB},
            standard::Standard,
        },
        simplex::{
            scheme::{Scheme, bls12381_multisig, bls12381_threshold, ed25519, secp256r1},
            types::{Finalization, Notarization, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    };
    use commonware_codec::{Decode, Encode};
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        Digest, Sha256 as Sha256Hasher,
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::{Scoped, mocks::Fixture},
        ed25519::PublicKey,
        sha256::Digest as Sha256,
    };
    use commonware_math::algebra::Random as _;
    use commonware_parallel::{Sequential, Strategy};
    use commonware_utils::{N3f1, non_empty, ordered::Quorum, sequence::Unit, test_rng};
    use rand_core::CryptoRng;
    use std::sync::Arc;

    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MARSHAL_SIZING";

    type StandardVariant = Standard<EmptyBlock<Sha256Hasher>>;
    type CodingVariant = Coding<CodingB, ReedSolomon<Sha256Hasher>, Sha256Hasher, PublicKey>;

    fn check_encoding<V: Variant, S: Scheme<V::Commitment>>(fixture: Fixture<S>) {
        let schemes = fixture.schemes;
        let certificate_max_size = fixture.verifier.certificate_max_size().unwrap();
        let overhead = max_recovery_overhead::<V>(&fixture.verifier).unwrap() as usize;
        let scoped = Scoped::verifier(Arc::new(fixture.verifier));
        assert_eq!(max_recovery_overhead::<V>(&scoped), Some(overhead as u32));
        for view in [1, 127, 128, u64::MAX] {
            let proposal = Proposal::new(
                Round::new(Epoch::new(view), View::new(view)),
                View::new(view - 1),
                V::Commitment::random(test_rng()),
            );
            for count in [
                schemes[0].participants().quorum::<S::Faults>() as usize,
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
                    let required = encoded.len() + MAX_RESPONSE_OVERHEAD as usize;
                    assert!(required <= overhead);
                    if view == u64::MAX && count == schemes.len() {
                        assert_eq!(required, overhead);
                    }
                }
            }
        }
    }

    #[test]
    fn fixed_certificate_overhead() {
        let mut rng = test_rng();
        check_encoding::<StandardVariant, _>(bls12381_threshold::standard::fixture::<MinSig, _>(
            &mut rng, NAMESPACE, 4,
        ));
        check_encoding::<StandardVariant, _>(bls12381_threshold::standard::fixture::<MinPk, _>(
            &mut rng, NAMESPACE, 4,
        ));
        check_encoding::<StandardVariant, _>(bls12381_threshold::vrf::fixture::<MinSig, _>(
            &mut rng, NAMESPACE, 4,
        ));
        check_encoding::<StandardVariant, _>(bls12381_threshold::vrf::fixture::<MinPk, _>(
            &mut rng, NAMESPACE, 4,
        ));
    }

    #[test]
    fn variable_certificate_overhead() {
        let mut rng = test_rng();
        for participants in [4, 128] {
            check_encoding::<StandardVariant, _>(ed25519::fixture(
                &mut rng,
                NAMESPACE,
                participants,
            ));
        }
        check_encoding::<StandardVariant, _>(secp256r1::fixture(&mut rng, NAMESPACE, 4));
        check_encoding::<StandardVariant, _>(bls12381_multisig::fixture::<MinSig, _>(
            &mut rng, NAMESPACE, 4,
        ));
        check_encoding::<StandardVariant, _>(bls12381_multisig::fixture::<MinPk, _>(
            &mut rng, NAMESPACE, 4,
        ));
    }

    #[test]
    fn coding_commitment_overhead() {
        check_encoding::<CodingVariant, _>(bls12381_threshold::vrf::fixture::<MinSig, _>(
            &mut test_rng(),
            NAMESPACE,
            4,
        ));
    }

    #[derive(Clone, Debug)]
    struct SizeVerifier(Option<usize>);

    impl Verifier for SizeVerifier {
        type Subject<'a, D: Digest> = Subject<'a, D>;
        type Faults = N3f1;
        type PublicKey = PublicKey;
        type Certificate = Unit;

        fn verify_certificate<R: CryptoRng, D: Digest>(
            &self,
            _: &mut R,
            _: Self::Subject<'_, D>,
            _: &Self::Certificate,
            _: &impl Strategy,
        ) -> bool {
            false
        }

        fn is_batchable() -> bool {
            false
        }

        fn certificate_max_size(&self) -> Option<usize> {
            self.0
        }

        fn certificate_codec_config(&self) {}

        fn certificate_codec_config_unbounded() {}
    }

    #[test]
    fn overhead_overflow() {
        let base = Sha256::SIZE + 3 * MAX_U64_VARINT_SIZE + MAX_RESPONSE_OVERHEAD as usize;
        let largest = u32::MAX as usize - base;
        for (size, expected) in [
            (Some(0), Some(base as u32)),
            (Some(largest), Some(u32::MAX)),
            (Some(largest + 1), None),
            (Some(usize::MAX), None),
            (None, None),
        ] {
            assert_eq!(
                max_recovery_overhead::<StandardVariant>(&SizeVerifier(size)),
                expected
            );
        }
    }
}
