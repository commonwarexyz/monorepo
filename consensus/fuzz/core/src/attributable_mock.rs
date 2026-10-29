//! The certificate scheme of [crate::simplex::SimplexCertificateMockAttributable]: the
//! attributable simplex certificate mock with each certificate's signers encoded in front
//! of its mock id, the layout of the attributable production schemes.
//!
//! The schemes of one [fixture] share a registry of the signers each id was assembled
//! from, and a certificate verifies only with those signers, so a valid id carrying
//! another signer set does not.

use crate::simplex_certificate_mock as cert_mock;
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{
    Digest,
    certificate::{
        self, AssemblyError, Attestation, Membership, Scheme as CertificateScheme, Signers,
        Verification, Verifier,
    },
    ed25519::PublicKey as Ed25519PublicKey,
};
use commonware_parallel::Strategy;
use commonware_utils::{
    bitmap::BitMap, iter::NonEmpty, non_empty, ordered::Set, sequence::U64, sync::Mutex,
};
use rand_core::CryptoRng;
use std::{collections::HashMap, sync::Arc};

/// The wrapped attributable certificate mock.
type Inner = cert_mock::Scheme<Ed25519PublicKey, true>;

/// A certificate: its signers, then the id the wrapped mock assembled.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    signers: Signers,
    id: U64,
}

impl Write for Certificate {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.id.write(writer);
    }
}

impl EncodeSize for Certificate {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.id.encode_size()
    }
}

impl Read for Certificate {
    /// The most participants the signers may span.
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, CodecError> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(CodecError::Invalid(
                "consensus::fuzz::attributable_mock::Certificate",
                "Certificate contains no signers",
            ));
        }
        let id = U64::read(reader)?;
        Ok(Self { signers, id })
    }
}

/// The signers of every id the schemes of one fixture assembled.
#[derive(Clone, Debug, Default)]
struct Registry(Arc<Mutex<HashMap<U64, Signers>>>);

/// The participants and schemes of an attributable mock fixture of `n`
/// participants. The schemes share one registry, as the wrapped mock numbers the
/// certificates of each fixture from 0.
pub fn fixture<R: CryptoRng>(
    rng: &mut R,
    namespace: &[u8],
    n: u32,
) -> (Vec<Ed25519PublicKey>, Vec<Scheme>) {
    let fixture = cert_mock::fixture_with::<true, true, true, _>(rng, namespace, n);
    let registry = Registry::default();
    let schemes = fixture
        .schemes
        .into_iter()
        .map(|inner| Scheme {
            inner,
            registry: registry.clone(),
        })
        .collect();
    (fixture.participants, schemes)
}

/// The attributable certificate mock with signers in its certificates. Everything
/// else delegates to the wrapped mock.
#[derive(Clone, Debug)]
pub struct Scheme {
    inner: Inner,
    registry: Registry,
}

impl Scheme {
    /// Whether `certificate` carries the signers its id was assembled from.
    fn recorded(&self, certificate: &Certificate) -> bool {
        self.registry.0.lock().get(&certificate.id) == Some(&certificate.signers)
    }

    fn to_inner(attestation: Attestation<Self>) -> Attestation<Inner> {
        Attestation {
            signer: attestation.signer,
            signature: attestation.signature,
        }
    }

    fn from_inner(attestation: Attestation<Inner>) -> Attestation<Self> {
        Attestation {
            signer: attestation.signer,
            signature: attestation.signature,
        }
    }
}

impl Verifier for Scheme {
    type Subject<'a, D: Digest> = <Inner as Verifier>::Subject<'a, D>;
    type Faults = <Inner as Verifier>::Faults;
    type PublicKey = Ed25519PublicKey;
    type Certificate = Certificate;

    fn verify_certificate<R, D>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        self.recorded(certificate)
            && self
                .inner
                .verify_certificate(rng, subject, &certificate.id, strategy)
    }

    fn is_batchable() -> bool {
        Inner::is_batchable()
    }

    fn max_certificate_size(participants: u32) -> usize {
        // The signers precede the id the wrapped mock assembled.
        BitMap::<1>::max_encode_size(u64::from(participants))
            + Inner::max_certificate_size(participants)
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.participants().len()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        u32::MAX as usize
    }
}

impl CertificateScheme for Scheme {
    type Signature = <Inner as CertificateScheme>::Signature;

    fn me(&self) -> Option<Membership> {
        self.inner.me()
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        self.inner.participants()
    }

    fn sign<D: Digest>(&self, subject: Self::Subject<'_, D>) -> Option<Attestation<Self>> {
        self.inner.sign(subject).map(Self::from_inner)
    }

    fn verify_attestation<R, D>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestation: &Attestation<Self>,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        self.inner
            .verify_attestation(rng, subject, &Self::to_inner(attestation.clone()), strategy)
    }

    fn verify_attestations<R, D, I>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestations: I,
        strategy: &impl Strategy,
    ) -> Verification<Self>
    where
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
    {
        let verification = self.inner.verify_attestations(
            rng,
            subject,
            attestations.into_iter().map(Self::to_inner),
            strategy,
        );
        Verification::new(
            verification
                .verified
                .into_iter()
                .map(Self::from_inner)
                .collect(),
            verification.invalid,
        )
    }

    fn optimistic_assemble<'a, R, D, I, J>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        pending: I,
        verified: J,
        strategy: &impl Strategy,
    ) -> Result<Self::Certificate, Verification<Self>>
    where
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: ExactSizeIterator + Send,
        J: IntoIterator<Item = &'a Attestation<Self>>,
        J::IntoIter: Send,
    {
        certificate::optimistic_assemble::<Self, _, D, _, _>(
            self, rng, subject, pending, verified, strategy,
        )
    }

    fn assemble<I>(
        &self,
        attestations: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> Result<Self::Certificate, AssemblyError>
    where
        I: Iterator<Item = Attestation<Self>> + Send,
    {
        let attestations: Vec<_> = attestations.into_iter().map(Self::to_inner).collect();
        let signers: Vec<_> = attestations
            .iter()
            .map(|attestation| attestation.signer)
            .collect();
        let id = self.inner.assemble(non_empty![@attestations], strategy)?;
        let signers = Signers::try_from((self.participants(), signers))?;
        let mut registry = self.registry.0.lock();
        let recorded = registry
            .entry(id.clone())
            .or_insert_with(|| signers.clone());
        assert_eq!(
            recorded, &signers,
            "mock certificate {id:?} was assembled from two signer sets"
        );
        Ok(Certificate { signers, id })
    }

    fn is_attributable() -> bool {
        Inner::is_attributable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EPOCH, NAMESPACE,
        simplex::{Simplex, SimplexCertificateMockAttributable},
    };
    use bytes::Bytes;
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_consensus::{
        simplex::types::{Notarization, Notarize, Proposal, Subject},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{Participant, test_rng};

    /// The schemes of a four-participant fixture of the attributable base, and a
    /// proposal notarized by participants 0, 1 and 2.
    fn notarized() -> (Vec<Scheme>, Proposal<Sha256Digest>, Certificate) {
        deterministic::Runner::default().start(|mut context| async move {
            let (_, schemes) =
                SimplexCertificateMockAttributable::setup(&mut context, NAMESPACE, 4);
            let proposal = Proposal::new(
                Round::new(Epoch::new(EPOCH), View::new(1)),
                View::zero(),
                Sha256Digest::from([1; 32]),
            );
            let votes: Vec<_> = schemes[..3]
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("a signer signs"))
                .collect();
            let notarization =
                Notarization::from_notarizes(&schemes[0], non_empty![@&votes], &Sequential)
                    .expect("a quorum assembles");
            (schemes, proposal, notarization.certificate)
        })
    }

    fn signers(indices: &[u32]) -> Signers {
        Signers::new(4, indices.iter().copied().map(Participant::new)).expect("valid signers")
    }

    #[test]
    fn a_certificate_with_altered_signers_fails_verification() {
        let (schemes, proposal, certificate) = notarized();
        let subject = || Subject::Notarize {
            proposal: &proposal,
        };
        let verifies = |certificate: &Certificate| {
            schemes[3].verify_certificate::<_, Sha256Digest>(
                &mut test_rng(),
                subject(),
                certificate,
                &Sequential,
            )
        };
        let batch_verifies = |certificate: &Certificate| {
            schemes[3].verify_certificates::<_, Sha256Digest, _>(
                &mut test_rng(),
                non_empty![(subject(), certificate)],
                &Sequential,
            )
        };
        assert_eq!(certificate.signers, signers(&[0, 1, 2]));
        assert!(verifies(&certificate));
        assert!(batch_verifies(&certificate));
        for altered in [&[0, 1, 3][..], &[0, 1, 2, 3], &[0, 1]] {
            let altered = Certificate {
                signers: signers(altered),
                id: certificate.id.clone(),
            };
            assert!(!verifies(&altered), "{altered:?}");
            assert!(!batch_verifies(&altered), "{altered:?}");
        }
    }

    #[test]
    fn a_certificate_with_an_unknown_id_fails_verification() {
        let (schemes, proposal, certificate) = notarized();
        let unknown = Certificate {
            signers: certificate.signers,
            id: U64::from(u64::MAX),
        };
        assert!(!schemes[3].verify_certificate::<_, Sha256Digest>(
            &mut test_rng(),
            Subject::Notarize {
                proposal: &proposal,
            },
            &unknown,
            &Sequential,
        ));
    }

    #[test]
    fn a_certificate_without_signers_does_not_decode() {
        let (schemes, _, certificate) = notarized();
        let empty = Certificate {
            signers: signers(&[]),
            id: certificate.id,
        };
        assert!(
            Certificate::decode_cfg(empty.encode(), &schemes[0].certificate_codec_config())
                .is_err()
        );
    }

    #[test]
    fn decoding_bounds_the_signers_and_rejects_malformed_bytes() {
        let (schemes, _, certificate) = notarized();
        let participants = schemes[0].certificate_codec_config();
        let encoded = certificate.encode();
        assert_eq!(
            Certificate::decode_cfg(encoded.clone(), &participants).expect("decodes"),
            certificate
        );
        assert!(Certificate::decode_cfg(encoded.clone(), &(participants - 1)).is_err());
        assert!(
            Certificate::decode_cfg(encoded.slice(..encoded.len() - 1), &participants).is_err()
        );
        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(Certificate::decode_cfg(Bytes::from(extended), &participants).is_err());
    }
}
