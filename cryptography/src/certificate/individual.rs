//! Attributable certificates that carry one signature per signer.
//!
//! [Generic] implements the certificate logic shared by signing primitives that offer neither
//! aggregation nor batch verification (such as [crate::secp256r1] and [crate::ml_dsa]): each
//! attestation is a standalone signature from the signer's key, attestations and certificates
//! are verified one signature at a time, and a [Certificate] stores the signatures of a quorum
//! ordered by signer index.
//!
//! Protocols instantiate [Generic] through a scheme-specific macro (such as
//! [crate::impl_certificate_secp256r1]) that binds it to their subject and namespace types.

#[cfg(feature = "mocks")]
pub mod mocks;

use crate::{
    Digest, Signer, Verifier as _,
    certificate::{AssemblyError, Attestation, Namespace, Scheme, Signers, Subject, Verification},
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, vec::Vec};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, Read, ReadRangeExt, Write, types::lazy::Lazy};
use commonware_utils::{
    Participant, Widen,
    iter::NonEmpty,
    ordered::{BiMap, Quorum, Set},
};
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

/// Generic individually-verified signing scheme parameterized by identity type `P`, signing
/// key type `K`, and namespace type `N`.
///
/// This struct contains the core cryptographic operations without protocol-specific
/// context types. It can be reused across different protocols (simplex, aggregation, etc.)
/// by wrapping it with protocol-specific trait implementations via a macro.
#[derive(Clone, Debug)]
pub struct Generic<P: crate::PublicKey, K: Signer, N: Namespace> {
    /// Participants in the committee.
    pub participants: BiMap<P, K::PublicKey>,
    /// Key used for generating signatures.
    pub signer: Option<(Participant, K)>,
    /// Pre-computed namespace(s) for this subject type.
    pub namespace: N,
}

impl<P: crate::PublicKey, K: Signer, N: Namespace> Generic<P, K, N> {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// Participants have both an identity key and a signing key. The identity key
    /// is used for participant set ordering and indexing, while the signing key is used for
    /// signing and verification.
    ///
    /// Returns `None` if the provided private key does not match any signing key
    /// in the participant set.
    pub fn signer(
        namespace: &[u8],
        participants: BiMap<P, K::PublicKey>,
        private_key: K,
    ) -> Option<Self> {
        let public_key = private_key.public_key();
        let signer = participants
            .values()
            .iter()
            .position(|p| p == &public_key)
            .map(|index| (Participant::from_usize(index), private_key))?;

        Some(Self {
            participants,
            signer: Some(signer),
            namespace: N::derive(namespace),
        })
    }

    /// Builds a verifier that can authenticate signatures and certificates.
    ///
    /// Participants have both an identity key and a signing key. The identity key
    /// is used for participant set ordering and indexing, while the signing key is used for
    /// verification.
    pub fn verifier(namespace: &[u8], participants: BiMap<P, K::PublicKey>) -> Self {
        Self {
            participants,
            signer: None,
            namespace: N::derive(namespace),
        }
    }

    /// Returns the ordered set of identity keys.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<Participant> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a subject and returns the attestation.
    pub fn sign<'a, S, D>(&self, subject: S::Subject<'a, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = K::Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let (index, private_key) = self.signer.as_ref()?;

        let signature = private_key.sign(subject.namespace(&self.namespace), &subject.message());

        Some(Attestation {
            signer: *index,
            signature: signature.into(),
        })
    }

    /// Verifies a single attestation from a signer.
    pub fn verify_attestation<'a, S, D>(
        &self,
        subject: S::Subject<'a, D>,
        attestation: &Attestation<S>,
    ) -> bool
    where
        S: Scheme<Signature = K::Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let Some(public_key) = self.participants.value(attestation.signer.into()) else {
            return false;
        };
        let Some(signature) = attestation.signature.get() else {
            return false;
        };

        public_key.verify(
            subject.namespace(&self.namespace),
            &subject.message(),
            signature,
        )
    }

    /// Verifies attestations one-by-one and returns verified attestations and invalid signers.
    pub fn verify_attestations<'a, S, R, D, I>(
        &self,
        _rng: &mut R,
        subject: S::Subject<'a, D>,
        attestations: I,
    ) -> Verification<S>
    where
        S: Scheme<Signature = K::Signature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
    {
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();

        let mut invalid = BTreeSet::new();
        let mut verified = Vec::new();

        for attestation in attestations.into_iter() {
            let Some(public_key) = self.participants.value(attestation.signer.into()) else {
                invalid.insert(attestation.signer);
                continue;
            };
            let Some(signature) = attestation.signature.get() else {
                invalid.insert(attestation.signer);
                continue;
            };

            if public_key.verify(namespace, &message, signature) {
                verified.push(attestation);
            } else {
                invalid.insert(attestation.signer);
            }
        }

        Verification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a non-empty collection of attestations.
    pub fn assemble<S, I>(
        &self,
        attestations: NonEmpty<I>,
    ) -> Result<Certificate<K::Signature>, AssemblyError>
    where
        S: Scheme<Signature = K::Signature>,
        I: Iterator<Item = Attestation<S>>,
    {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for Attestation { signer, signature } in attestations {
            self.participants
                .value(signer.into())
                .ok_or(AssemblyError::UnknownSigner(signer))?;
            let signature = signature
                .get()
                .cloned()
                .ok_or(AssemblyError::MalformedSignature(signer))?;
            entries.push((signer, signature));
        }

        // Sort the signatures by signer index.
        entries.sort_by_key(|(signer, _)| *signer);
        let (signer, signatures): (Vec<Participant>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::try_from((self.participants.keys(), signer))?
            .require(self.participants.quorum::<S::Faults>())?;
        let signatures = signatures.into_iter().map(Lazy::from).collect();

        Ok(Certificate {
            signers,
            signatures,
        })
    }

    /// Verifies a certificate by checking each signature individually.
    pub fn verify_certificate<'a, S, R, D>(
        &self,
        _rng: &mut R,
        subject: S::Subject<'a, D>,
        certificate: &Certificate<K::Signature>,
    ) -> bool
    where
        S: Scheme,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRng,
        D: Digest,
    {
        // If the certificate signers length does not match the participant set, return false.
        if certificate.signers.len() != self.participants.len() {
            return false;
        }

        // If the certificate signers and signatures counts differ, return false.
        if certificate.signers.count() != certificate.signatures.len() {
            return false;
        }

        // If the certificate does not meet the quorum, return false.
        if certificate.signers.count() < Widen::widen(self.participants.quorum::<S::Faults>()) {
            return false;
        }

        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.value(signer.into()) else {
                return false;
            };
            let Some(signature) = signature.get() else {
                return false;
            };
            if !public_key.verify(namespace, &message, signature) {
                return false;
            }
        }

        true
    }

    pub const fn is_attributable() -> bool {
        true
    }

    pub const fn is_batchable() -> bool {
        false
    }

    pub const fn certificate_codec_config(
        &self,
    ) -> <Certificate<K::Signature> as commonware_codec::Read>::Cfg {
        self.participants.len()
    }

    pub const fn certificate_codec_config_unbounded()
    -> <Certificate<K::Signature> as commonware_codec::Read>::Cfg {
        u32::MAX as usize
    }
}

/// Certificate containing one signature per contributing participant.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<S: crate::Signature> {
    /// Bitmap of participant indices that contributed signatures.
    pub signers: Signers,
    /// Signatures emitted by the respective participants ordered by signer index.
    pub signatures: Vec<Lazy<S>>,
}

#[cfg(feature = "arbitrary")]
impl<S> arbitrary::Arbitrary<'_> for Certificate<S>
where
    S: crate::Signature + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signers = Signers::arbitrary(u)?;
        let signatures = (0..signers.count())
            .map(|_| u.arbitrary::<S>().map(Lazy::from))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self {
            signers,
            signatures,
        })
    }
}

impl<S: crate::Signature> Write for Certificate<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signatures.write(writer);
    }
}

impl<S: crate::Signature> EncodeSize for Certificate<S> {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signatures.encode_size()
    }
}

impl<S: crate::Signature> Read for Certificate<S> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "cryptography::certificate::individual::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signatures = Vec::<Lazy<S>>::read_range(reader, ..=*participants)?;
        if signers.count() != signatures.len() {
            return Err(Error::Invalid(
                "cryptography::certificate::individual::Certificate",
                "Signers and signatures counts differ",
            ));
        }

        Ok(Self {
            signers,
            signatures,
        })
    }
}
