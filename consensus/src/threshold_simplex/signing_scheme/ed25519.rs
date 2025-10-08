use crate::threshold_simplex::{
    signing_scheme::{finalize_namespace, notarize_namespace, nullify_namespace},
    types::{Participants, SigningScheme, Vote, VoteContext, VoteVerification},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadRangeExt, Write};
use commonware_cryptography::{
    ed25519::{Batch, PrivateKey, PublicKey, Signature as Ed25519Signature},
    BatchVerifier, Digest, Signer as _, Verifier as _,
};
use rand::{CryptoRng, Rng};
use std::collections::BTreeSet;

/// Ed25519 implementation of the [`SigningScheme`] trait.
#[derive(Clone, Debug)]
pub struct Scheme {
    participants: Participants<PublicKey>,
    signer: Option<(u32, PrivateKey)>,
}

impl Scheme {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// * `participants` - ordered validator set used for verification.
    /// * `signer_index` - index of the local validator in the participant set.
    /// * `private_key` - optional secret key enabling signing capabilities.
    pub fn new(participants: Vec<PublicKey>, signer_index: u32, private_key: PrivateKey) -> Self {
        assert!(
            (signer_index as usize) < participants.len(),
            "signer index {} is out of bounds for validator set of size {}",
            signer_index,
            participants.len()
        );

        Self {
            participants: participants.into(),
            signer: Some((signer_index, private_key)),
        }
    }

    pub fn verifier(participants: Vec<PublicKey>) -> Self {
        Self {
            participants: participants.into(),
            signer: None,
        }
    }

    /// Converts the scheme into a pure verifier by removing the private key.
    pub fn into_verifier(mut self) -> Self {
        self.signer = None;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    pub signers: Vec<u32>,
    pub signatures: Vec<Ed25519Signature>,
}

impl Write for Certificate {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signatures.write(writer);
    }
}

impl EncodeSize for Certificate {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signatures.encode_size()
    }
}

impl Read for Certificate {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let signers = Vec::<u32>::read_range(reader, ..=*participants)?;
        let signatures = Vec::<Ed25519Signature>::read_range(reader, ..=*participants)?;

        if signers.len() != signatures.len() {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::signing_scheme::ed25519::Certificate",
                "Signers and signatures counts differ",
            ));
        }

        if signers.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::signing_scheme::ed25519::Certificate",
                "Signatures are not sorted by public key index",
            ));
        }

        let certificate = Self {
            signers,
            signatures,
        };

        if certificate
            .signers
            .iter()
            .any(|signer| (*signer as usize) >= *participants)
        {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::signing_scheme::ed25519::Certificate",
                "Signer index exceeds participant set",
            ));
        }

        Ok(certificate)
    }
}

impl SigningScheme for Scheme {
    type Signature = Ed25519Signature;
    type Certificate = Certificate;
    type Randomness = ();

    type CertificateCfg = usize;

    fn can_sign(&self) -> bool {
        self.signer.is_some()
    }

    fn sign_vote<D: Digest>(&self, namespace: &[u8], context: VoteContext<'_, D>) -> Vote<Self> {
        let (index, private_key) = self
            .signer
            .as_ref()
            .expect("can only be called after checking can_sign");

        let (domain, message) = match context {
            VoteContext::Notarize { proposal } => {
                (notarize_namespace(namespace), proposal.encode())
            }
            VoteContext::Nullify { round } => (nullify_namespace(namespace), round.encode()),
            VoteContext::Finalize { proposal } => {
                (finalize_namespace(namespace), proposal.encode())
            }
        };

        let signature = private_key.sign(Some(domain.as_ref()), message.as_ref());

        Vote {
            signer: *index,
            signature,
        }
    }

    fn verify_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        vote: &Vote<Self>,
    ) -> bool {
        let Some(public_key) = self.participants.get(vote.signer) else {
            return false;
        };

        let (domain, message) = match context {
            VoteContext::Notarize { proposal } => {
                (notarize_namespace(namespace), proposal.encode())
            }
            VoteContext::Nullify { round } => (nullify_namespace(namespace), round.encode()),
            VoteContext::Finalize { proposal } => {
                (finalize_namespace(namespace), proposal.encode())
            }
        };

        public_key.verify(Some(domain.as_ref()), message.as_ref(), &vote.signature)
    }

    fn verify_votes<R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        votes: I,
    ) -> VoteVerification<Self>
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Vote<Self>>,
    {
        let (domain, message) = match context {
            VoteContext::Notarize { proposal } => {
                (notarize_namespace(namespace), proposal.encode())
            }
            VoteContext::Nullify { round } => (nullify_namespace(namespace), round.encode()),
            VoteContext::Finalize { proposal } => {
                (finalize_namespace(namespace), proposal.encode())
            }
        };

        let mut invalid = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut batch = Batch::new();

        for vote in votes.into_iter() {
            let Some(public_key) = self.participants.get(vote.signer) else {
                invalid.insert(vote.signer);
                continue;
            };

            batch.add(
                Some(domain.as_ref()),
                message.as_ref(),
                public_key,
                &vote.signature,
            );

            candidates.push((vote, public_key));
        }

        if !candidates.is_empty() && !batch.verify(rng) {
            for (vote, public_key) in &candidates {
                if !public_key.verify(Some(domain.as_ref()), message.as_ref(), &vote.signature) {
                    invalid.insert(vote.signer);
                }
            }
        }

        let verified = candidates
            .into_iter()
            .filter_map(|(vote, _)| {
                if invalid.contains(&vote.signer) {
                    None
                } else {
                    Some(vote)
                }
            })
            .collect();

        VoteVerification::new(verified, invalid.into_iter().collect())
    }

    fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Vote<Self>>,
    {
        let mut entries = Vec::new();

        for Vote { signer, signature } in votes {
            if signer as usize >= self.participants.len() {
                return None;
            }

            entries.push((signer, signature));
        }

        if entries.len() < self.participants.quorum() as usize {
            return None;
        }

        entries.sort_by_key(|(signer, _)| *signer);
        let (signers, signatures): (Vec<_>, Vec<_>) = entries.into_iter().unzip();

        Some(Certificate {
            signers,
            signatures,
        })
    }

    fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        certificate: &Self::Certificate,
    ) -> bool {
        if certificate.signers.len() < self.participants.quorum() as usize {
            return false;
        }

        let (domain, message) = match context {
            VoteContext::Notarize { proposal } => {
                (notarize_namespace(namespace), proposal.encode())
            }
            VoteContext::Nullify { round } => (nullify_namespace(namespace), round.encode()),
            VoteContext::Finalize { proposal } => {
                (finalize_namespace(namespace), proposal.encode())
            }
        };

        let mut batch = Batch::new();
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.get(*signer) else {
                return false;
            };

            batch.add(
                Some(domain.as_ref()),
                message.as_ref(),
                public_key,
                signature,
            );
        }

        batch.verify(rng)
    }

    fn verify_certificates<'a, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        certificates: I,
    ) -> bool
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: Iterator<Item = (VoteContext<'a, D>, &'a Self::Certificate)>,
    {
        let mut batch = Batch::new();

        for (context, certificate) in certificates {
            if certificate.signers.len() < self.participants.quorum() as usize {
                return false;
            }

            let (domain, message) = match context {
                VoteContext::Notarize { proposal } => {
                    (notarize_namespace(namespace), proposal.encode())
                }
                VoteContext::Nullify { round } => (nullify_namespace(namespace), round.encode()),
                VoteContext::Finalize { proposal } => {
                    (finalize_namespace(namespace), proposal.encode())
                }
            };

            for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
                let Some(public_key) = self.participants.get(*signer) else {
                    return false;
                };

                batch.add(
                    Some(domain.as_ref()),
                    message.as_ref(),
                    public_key,
                    signature,
                );
            }
        }

        batch.verify(rng)
    }

    fn randomness(&self, _: &Self::Certificate) -> Option<Self::Randomness> {
        None
    }

    fn certificate_codec_config(&self) -> Self::CertificateCfg {
        self.participants.len()
    }
}
