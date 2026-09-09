use commonware_codec::varint::MAX_U64_VARINT_SIZE;
use commonware_cryptography::{Digest, certificate::Verifier};
use commonware_resolver::p2p::MAX_RESPONSE_OVERHEAD;

/// Returns the maximum recovery overhead beyond the encoded recovered block, in bytes.
///
/// The configured verifier bounds its underlying certificate encoding, including all accepted
/// signer counts. When recovering multiple epochs or committees, use the largest overhead
/// across their verifiers.
///
/// `C` is the consensus payload digest: the block digest for standard marshal or the
/// commitment for coding marshal. The result includes the proposal and P2P resolver response
/// framing. Add it to the maximum complete encoded recovered block size and check the sum
/// against the P2P application message limit. For coding marshal, budgeting the full encoded
/// coded block, including its coding configuration, covers all recovery paths.
///
/// Returns `None` if the verifier cannot bound certificate size or the overhead cannot fit
/// in a `u32`.
///
/// # Examples
///
/// Bound the encoded block size for standard marshal with SHA-256 block digests:
///
/// ```
/// use commonware_consensus::marshal::max_recovery_overhead;
/// use commonware_cryptography::{certificate::Verifier, sha256::Digest};
///
/// fn max_block_size<S: Verifier>(scheme: &S, max_message_size: u32) -> Option<u32> {
///     let overhead = max_recovery_overhead::<_, Digest>(scheme)?;
///     max_message_size.checked_sub(overhead)
/// }
/// ```
pub fn max_recovery_overhead<S: Verifier, C: Digest>(scheme: &S) -> Option<u32> {
    scheme
        .certificate_max_size()?
        .checked_add(C::SIZE)?
        .checked_add(3 * MAX_U64_VARINT_SIZE)?
        .checked_add(MAX_RESPONSE_OVERHEAD as usize)?
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::mocks::block::EmptyBlock,
        simplex::{
            scheme::{Scheme, bls12381_multisig, bls12381_threshold, ed25519, secp256r1},
            types::{Finalization, Notarization, Proposal, Subject},
        },
        types::{Epoch, Round, View, coding::Commitment},
    };
    use commonware_codec::{Decode, Encode, FixedSize};
    use commonware_coding::ReedSolomon;
    use commonware_cryptography::{
        Sha256 as Sha256Hasher,
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::{Scoped, mocks::Fixture},
        ed25519::PublicKey,
        sha256::Digest as Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{N3f1, non_empty, ordered::Quorum, sequence::Unit, test_rng};
    use std::sync::Arc;

    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MARSHAL_SIZING";

    fn check_encoding<S: Scheme<C>, C: Digest>(fixture: Fixture<S>) {
        let schemes = fixture.schemes;
        let certificate_max_size = fixture.verifier.certificate_max_size().unwrap();
        let overhead = max_recovery_overhead::<_, C>(&fixture.verifier).unwrap() as usize;
        let scoped = Scoped::verifier(Arc::new(fixture.verifier));
        assert_eq!(
            max_recovery_overhead::<_, C>(&scoped),
            Some(overhead as u32)
        );
        for view in [1, 127, 128, u64::MAX] {
            let proposal = Proposal::new(
                Round::new(Epoch::new(view), View::new(view)),
                View::new(view - 1),
                C::random(test_rng()),
            );
            for count in [
                schemes[0].participants().quorum::<S::Faults>() as usize,
                schemes.len(),
            ] {
                let attestations = schemes.iter().take(count).map(|scheme| {
                    scheme
                        .sign::<C>(Subject::Notarize {
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
                let notarization = Notarization::<S, C> {
                    proposal: proposal.clone(),
                    certificate: certificate.clone(),
                };
                let finalization = Finalization::<S, C> {
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
        check_encoding::<_, Sha256>(bls12381_threshold::standard::fixture::<MinSig, _>(
            &mut rng, NAMESPACE, 4,
        ));
        check_encoding::<_, Sha256>(bls12381_threshold::standard::fixture::<MinPk, _>(
            &mut rng, NAMESPACE, 4,
        ));
        check_encoding::<_, Sha256>(bls12381_threshold::vrf::fixture::<MinSig, _>(
            &mut rng, NAMESPACE, 4,
        ));
        check_encoding::<_, Sha256>(bls12381_threshold::vrf::fixture::<MinPk, _>(
            &mut rng, NAMESPACE, 4,
        ));
    }

    #[test]
    fn variable_certificate_overhead() {
        let mut rng = test_rng();
        for participants in [4, 128] {
            check_encoding::<_, Sha256>(ed25519::fixture(&mut rng, NAMESPACE, participants));
        }
        check_encoding::<_, Sha256>(secp256r1::fixture(&mut rng, NAMESPACE, 4));
        check_encoding::<_, Sha256>(bls12381_multisig::fixture::<MinSig, _>(
            &mut rng, NAMESPACE, 4,
        ));
        check_encoding::<_, Sha256>(bls12381_multisig::fixture::<MinPk, _>(
            &mut rng, NAMESPACE, 4,
        ));
    }

    #[test]
    fn coding_commitment_overhead() {
        type C = Commitment<EmptyBlock<Sha256Hasher>, ReedSolomon<Sha256Hasher>, Sha256Hasher>;
        check_encoding::<_, C>(bls12381_threshold::vrf::fixture::<MinSig, _>(
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

        fn verify_certificate<R: rand_core::CryptoRng, D: Digest>(
            &self,
            _: &mut R,
            _: Self::Subject<'_, D>,
            _: &Self::Certificate,
            _: &impl commonware_parallel::Strategy,
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
                max_recovery_overhead::<_, Sha256>(&SizeVerifier(size)),
                expected
            );
        }
    }
}
