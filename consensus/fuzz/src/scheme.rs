use bytes::{Buf, BufMut};
use commonware_codec::{
    types::lazy::Lazy, EncodeSize, Error, FixedSize, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_consensus::simplex::types::Subject;
use commonware_cryptography::{
    certificate::{self, Attestation, Signers},
    Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::{
    ordered::{Quorum, Set},
    sequence::U32,
    Array, Faults, Participant, Span, TryCollect,
};
use core::{
    fmt::{Display, Formatter},
    ops::Deref,
};
use rand::{CryptoRng, RngCore};

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct Identity(U32);

impl Identity {
    pub const fn from_index(index: u32) -> Self {
        Self(U32::new(index))
    }

    pub fn index(&self) -> u32 {
        u32::from(&self.0)
    }
}

impl commonware_cryptography::Signature for Identity {}

impl Write for Identity {
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}

impl Read for Identity {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self(U32::read(reader)?))
    }
}

impl FixedSize for Identity {
    const SIZE: usize = U32::SIZE;
}

impl Span for Identity {}

impl Array for Identity {}

impl AsRef<[u8]> for Identity {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for Identity {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeySignature({})", self.index())
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.index())
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct PublicKey(U32);

impl PublicKey {
    pub const fn from_index(index: u32) -> Self {
        Self(U32::new(index))
    }

    pub fn index(&self) -> u32 {
        u32::from(&self.0)
    }
}

impl commonware_cryptography::Verifier for PublicKey {
    type Signature = Identity;

    fn verify(&self, _namespace: &[u8], _msg: &[u8], sig: &Self::Signature) -> bool {
        sig.index() == self.index()
    }
}

impl commonware_cryptography::PublicKey for PublicKey {}

impl Write for PublicKey {
    fn write(&self, writer: &mut impl BufMut) {
        self.0.write(writer);
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self(U32::read(reader)?))
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = U32::SIZE;
}

impl Span for PublicKey {}

impl Array for PublicKey {}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for PublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey({})", self.index())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.index())
    }
}

/// Identity-like signature used in the fuzz tests only.
///
/// A signature is valid when:
/// - the attestation signer index is in the participant set, and
/// - the signature carries the same signer index, and
/// - the signature's valid flag is true.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    pub signer: u32,
    pub valid: bool,
}

impl Write for Signature {
    fn write(&self, writer: &mut impl BufMut) {
        self.signer.write(writer);
        self.valid.write(writer);
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            signer: u32::read(reader)?,
            valid: bool::read(reader)?,
        })
    }
}

impl FixedSize for Signature {
    const SIZE: usize = u32::SIZE + bool::SIZE;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    pub signers: Signers,
    pub signatures: Vec<Lazy<Signature>>,
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
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "consensus::fuzz::scheme::Certificate",
                "certificate contains no signers",
            ));
        }

        let signatures = Vec::<Lazy<Signature>>::read_range(reader, ..=*participants)?;
        if signers.count() != signatures.len() {
            return Err(Error::Invalid(
                "consensus::fuzz::scheme::Certificate",
                "signers and signatures counts differ",
            ));
        }

        Ok(Self {
            signers,
            signatures,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Scheme {
    participants: Set<PublicKey>,
    signer: Option<Participant>,
}

impl Scheme {
    pub fn signer(participants: Set<PublicKey>, signer: Participant) -> Self {
        Self {
            participants,
            signer: Some(signer),
        }
    }

    pub fn verifier(participants: Set<PublicKey>) -> Self {
        Self {
            participants,
            signer: None,
        }
    }
}

/// Builds identities and mock scheme instances for fuzz tests.
pub fn fixture<R>(_: &mut R, _: &[u8], n: u32) -> (Vec<PublicKey>, Vec<Scheme>)
where
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let participants: Vec<_> = (0..n).map(PublicKey::from_index).collect();
    let participant_set = participants
        .iter()
        .cloned()
        .try_collect::<Set<PublicKey>>()
        .expect("index-based public keys are unique");
    let schemes = (0..n)
        .map(|index| Scheme::signer(participant_set.clone(), Participant::new(index)))
        .collect();

    (participants, schemes)
}

impl certificate::Scheme for Scheme {
    type Subject<'a, D: Digest> = Subject<'a, D>;
    type PublicKey = PublicKey;
    type Signature = Signature;
    type Certificate = Certificate;

    fn me(&self) -> Option<Participant> {
        self.signer
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        &self.participants
    }

    fn sign<D: Digest>(&self, _subject: Self::Subject<'_, D>) -> Option<Attestation<Self>> {
        let signer = self.signer?;
        Some(Attestation {
            signer,
            signature: Signature {
                signer: signer.get(),
                valid: true,
            }
            .into(),
        })
    }

    fn verify_attestation<R, D>(
        &self,
        _rng: &mut R,
        _subject: Self::Subject<'_, D>,
        attestation: &Attestation<Self>,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRngCore,
        D: Digest,
    {
        if self.participants.key(attestation.signer).is_none() {
            return false;
        }

        let Some(signature) = attestation.signature.get() else {
            return false;
        };

        signature.signer == attestation.signer.get() && signature.valid
    }

    fn assemble<I, M>(
        &self,
        attestations: I,
        _strategy: &impl Strategy,
    ) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
        M: Faults,
    {
        let mut entries = Vec::new();
        for Attestation { signer, signature } in attestations {
            if usize::from(signer) >= self.participants.len() {
                return None;
            }
            let signature = signature.get().cloned()?;
            if signature.signer != signer.get() || !signature.valid {
                return None;
            }
            entries.push((signer, signature));
        }

        if entries.len() < self.participants.quorum::<M>() as usize {
            return None;
        }

        entries.sort_by_key(|(signer, _)| *signer);
        let signers = Signers::from(self.participants.len(), entries.iter().map(|(s, _)| *s));
        let signatures = entries.into_iter().map(|(_, sig)| sig.into()).collect();

        Some(Certificate {
            signers,
            signatures,
        })
    }

    fn verify_certificate<R, D, M>(
        &self,
        _rng: &mut R,
        _subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRngCore,
        D: Digest,
        M: Faults,
    {
        if certificate.signers.len() != self.participants.len() {
            return false;
        }
        if certificate.signers.count() != certificate.signatures.len() {
            return false;
        }
        if certificate.signers.count() < self.participants.quorum::<M>() as usize {
            return false;
        }

        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            if self.participants.key(signer).is_none() {
                return false;
            }
            let Some(signature) = signature.get() else {
                return false;
            };
            if signature.signer != signer.get() || !signature.valid {
                return false;
            }
        }

        true
    }

    fn is_attributable() -> bool {
        true
    }

    fn is_batchable() -> bool {
        false
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.participants.len()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        u32::MAX as usize
    }
}
