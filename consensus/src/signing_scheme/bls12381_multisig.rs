use crate::signing_scheme::utils::Signers;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::bls12381::primitives::{
    group::Private,
    ops::{
        aggregate_signatures, aggregate_verify_multiple_public_keys, compute_public, sign_message,
        verify_message,
    },
    variant::Variant,
};
use rand::{CryptoRng, Rng};

/// Core BLS12-381 multi-signature implementation.
#[derive(Clone, Debug)]
pub struct Bls12381Multisig<V: Variant> {
    /// Consensus public keys for verification.
    pub consensus_keys: Vec<V::Public>,
    /// Key used for generating signatures.
    pub signer: Option<(u32, Private)>,
    /// Quorum size for certificate assembly.
    pub quorum: u32,
}

impl<V: Variant> Bls12381Multisig<V> {
    /// Creates a new raw BLS12-381 multisig scheme instance.
    pub fn new(consensus_keys: Vec<V::Public>, private_key: Private, quorum: u32) -> Self {
        let public_key = compute_public::<V>(&private_key);
        let signer = consensus_keys
            .iter()
            .position(|p| p == &public_key)
            .map(|index| (index as u32, private_key));

        Self {
            consensus_keys,
            signer,
            quorum,
        }
    }

    /// Builds a verifier that can authenticate votes and certificates.
    pub fn verifier(consensus_keys: Vec<V::Public>, quorum: u32) -> Self {
        Self {
            consensus_keys,
            signer: None,
            quorum,
        }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<u32> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a message and returns the signer index and signature.
    pub fn sign_vote(&self, namespace: &[u8], message: &[u8]) -> Option<(u32, V::Signature)> {
        let (index, private_key) = self.signer.as_ref()?;
        let signature = sign_message::<V>(private_key, Some(namespace), message);
        Some((*index, signature))
    }

    /// Verifies a single vote from a signer.
    pub fn verify_vote(
        &self,
        namespace: &[u8],
        message: &[u8],
        signer: u32,
        signature: &V::Signature,
    ) -> bool {
        let Some(public_key) = self.consensus_keys.get(signer as usize) else {
            return false;
        };
        verify_message::<V>(public_key, Some(namespace), message, signature).is_ok()
    }

    /// Batch-verifies votes using aggregate verification.
    ///
    /// Returns verified votes and invalid signers.
    pub fn verify_votes<R: Rng + CryptoRng>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        message: &[u8],
        votes: impl IntoIterator<Item = (u32, V::Signature)>,
    ) -> (Vec<(u32, V::Signature)>, Vec<u32>) {
        let mut invalid = Vec::new();
        let mut candidates = Vec::new();
        let mut publics = Vec::new();
        let mut signatures = Vec::new();

        for (signer, signature) in votes {
            let Some(public_key) = self.consensus_keys.get(signer as usize) else {
                invalid.push(signer);
                continue;
            };

            publics.push(*public_key);
            signatures.push(signature);
            candidates.push((signer, signature));
        }

        // If there are no candidates to verify, return before doing any work.
        if candidates.is_empty() {
            return (candidates, invalid);
        }

        // Verify the aggregate signature.
        if aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace),
            message,
            &aggregate_signatures::<V, _>(signatures.iter()),
        )
        .is_err()
        {
            // Aggregate failed: fall back to per-signer verification.
            for ((signer, sig), public_key) in candidates.iter().zip(publics.iter()) {
                if verify_message::<V>(public_key, Some(namespace), message, sig).is_err() {
                    invalid.push(*signer);
                }
            }
        }

        let verified = candidates
            .into_iter()
            .filter(|(signer, _)| !invalid.contains(signer))
            .collect();

        (verified, invalid)
    }

    /// Assembles a certificate from a collection of votes.
    pub fn assemble_certificate(
        &self,
        votes: impl IntoIterator<Item = (u32, V::Signature)>,
    ) -> Option<Certificate<V>> {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for (signer, signature) in votes {
            if (signer as usize) >= self.consensus_keys.len() {
                return None;
            }
            entries.push((signer, signature));
        }
        if entries.len() < self.quorum as usize {
            return None;
        }

        // Produce signers and aggregate signature.
        let (signers, signatures): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.consensus_keys.len(), signers);
        let signature = aggregate_signatures::<V, _>(signatures.iter());

        Some(Certificate { signers, signature })
    }

    /// Verifies a certificate.
    pub fn verify_certificate<R: Rng + CryptoRng>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        message: &[u8],
        certificate: &Certificate<V>,
    ) -> bool {
        // If the certificate signers length does not match the participant set, return false.
        if certificate.signers.len() != self.consensus_keys.len() {
            return false;
        }

        // If the certificate does not meet the quorum, return false.
        if certificate.signers.count() < self.quorum as usize {
            return false;
        }

        // Collect the public keys.
        let mut publics = Vec::with_capacity(certificate.signers.count());
        for signer in certificate.signers.iter() {
            let Some(public_key) = self.consensus_keys.get(signer as usize) else {
                return false;
            };
            publics.push(*public_key);
        }

        // Verify the aggregate signature.
        aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace),
            message,
            &certificate.signature,
        )
        .is_ok()
    }

    /// Verifies multiple certificates (no batch optimization for BLS multisig).
    pub fn verify_certificates<'a, R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        certificates: impl Iterator<Item = (&'a [u8], &'a [u8], &'a Certificate<V>)>,
    ) -> bool {
        for (namespace, message, certificate) in certificates {
            if !self.verify_certificate(rng, namespace, message, certificate) {
                return false;
            }
        }
        true
    }
}

/// Certificate formed by an aggregated BLS12-381 signature plus the signers that
/// contributed to it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<V: Variant> {
    /// Bitmap of validator indices that contributed signatures.
    pub signers: Signers,
    /// Aggregated BLS signature covering all votes in this certificate.
    pub signature: V::Signature,
}

impl<V: Variant> Write for Certificate<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant> EncodeSize for Certificate<V> {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signature.encode_size()
    }
}

impl<V: Variant> Read for Certificate<V> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::bls12381_multisig::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signature = V::Signature::read(reader)?;

        Ok(Self { signers, signature })
    }
}
