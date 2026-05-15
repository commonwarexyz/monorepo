use crate::{simplex::elector, types::Round};
use commonware_codec::{types::lazy::Lazy, Encode};
use commonware_cryptography::{
    certificate::{Attestation, Verification},
    sha256::Sha256,
    Hasher as _,
};
use commonware_parallel::Sequential;
use commonware_utils::{modulo, test_rng, Faults, Participant};
use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behavior {
    Honest,
    CorruptSignature,
}

#[derive(Clone, Debug)]
pub struct Scheme<S> {
    inner: S,
    behavior: Behavior,
}

#[derive(Clone, Debug)]
pub struct Elector<E, S> {
    inner: E,
    _phantom: std::marker::PhantomData<S>,
}

#[derive(Clone, Debug, Default)]
pub struct Config<L>(pub L);

impl<S> Scheme<S> {
    pub const fn new(inner: S, behavior: Behavior) -> Self {
        Self { inner, behavior }
    }

    fn to_inner_attestation(attestation: &Attestation<Self>) -> Attestation<S>
    where
        S: commonware_cryptography::certificate::Scheme,
    {
        Attestation {
            signer: attestation.signer,
            signature: attestation.signature.clone(),
        }
    }

    fn from_inner_attestation(attestation: Attestation<S>) -> Attestation<Self>
    where
        S: commonware_cryptography::certificate::Scheme,
    {
        Attestation {
            signer: attestation.signer,
            signature: attestation.signature,
        }
    }

    fn corrupt_signature<D>(
        inner: &S,
        subject: <S as commonware_cryptography::certificate::Scheme>::Subject<'_, D>,
        signer: Participant,
        signature: &<S as commonware_cryptography::certificate::Scheme>::Signature,
    ) -> Lazy<<S as commonware_cryptography::certificate::Scheme>::Signature>
    where
        S: commonware_cryptography::certificate::Scheme,
        D: commonware_cryptography::Digest,
    {
        let encoded = signature.encode().to_vec();
        let bit_len = encoded.len() * 8;

        // Hash the signer and signature bytes to derive a deterministic starting
        // point for the single-bit flip search.
        let mut hasher = Sha256::default();
        hasher.update(&signer.encode());
        hasher.update(&encoded);
        let digest = hasher.finalize();

        // Start from a deterministic but non-trivial bit so tests do not always
        // mutate the same low-order bit first.
        let start = modulo(digest.as_ref(), bit_len as u64) as usize;

        // Search all single-bit mutations, wrapping around from `start`, until
        // we find one that still decodes as a signature but fails verification.
        (0..bit_len)
            .find_map(|offset| {
                let flip = (start + offset) % bit_len;
                let byte = flip / 8;
                let bit = flip % 8;
                let mut corrupted = encoded.clone();
                corrupted[byte] ^= 1 << bit;

                // `Lazy` lets us reject undecodable byte patterns before asking
                // the wrapped scheme whether the mutated attestation verifies.
                let lazy = Lazy::deferred(&mut corrupted.as_slice(), ());
                let attestation = Attestation {
                    signer,
                    signature: lazy.clone(),
                };
                (lazy.get().is_some()
                    && !inner.verify_attestation(
                        &mut test_rng(),
                        subject.clone(),
                        &attestation,
                        &Sequential,
                    ))
                .then_some(lazy)
            })
            .expect("expected at least one invalid but decodable signature mutation")
    }
}

impl<S, L> elector::Config<Scheme<S>> for Config<L>
where
    S: commonware_cryptography::certificate::Scheme,
    L: elector::Config<S>,
{
    type Elector = Elector<L::Elector, S>;

    fn build(
        self,
        participants: &commonware_utils::ordered::Set<
            <Scheme<S> as commonware_cryptography::certificate::Scheme>::PublicKey,
        >,
        term_length: NonZeroU64,
    ) -> Self::Elector {
        Elector {
            inner: self.0.build(participants, term_length),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S, E> elector::Elector<Scheme<S>> for Elector<E, S>
where
    S: commonware_cryptography::certificate::Scheme,
    E: elector::Elector<S>,
{
    fn elect(
        &self,
        round: Round,
        certificate: Option<
            &<Scheme<S> as commonware_cryptography::certificate::Scheme>::Certificate,
        >,
    ) -> Participant {
        self.inner.elect(round, certificate)
    }
}

impl<S> commonware_cryptography::certificate::Scheme for Scheme<S>
where
    S: commonware_cryptography::certificate::Scheme,
{
    type Subject<'a, D: commonware_cryptography::Digest> = S::Subject<'a, D>;
    type PublicKey = S::PublicKey;
    type Signature = S::Signature;
    type Certificate = S::Certificate;

    fn me(&self) -> Option<Participant> {
        self.inner.me()
    }

    fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
        self.inner.participants()
    }

    fn sign<D: commonware_cryptography::Digest>(
        &self,
        subject: Self::Subject<'_, D>,
    ) -> Option<Attestation<Self>> {
        let attestation = self.inner.sign(subject.clone())?;
        let signature = match self.behavior {
            Behavior::Honest => attestation.signature,
            Behavior::CorruptSignature => {
                let signature = attestation
                    .signature
                    .get()
                    .expect("fresh signature should decode");
                Self::corrupt_signature(&self.inner, subject, attestation.signer, signature)
            }
        };

        Some(Attestation {
            signer: attestation.signer,
            signature,
        })
    }

    fn verify_attestation<R, D>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestation: &Attestation<Self>,
        strategy: &impl commonware_parallel::Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRngCore,
        D: commonware_cryptography::Digest,
    {
        self.inner.verify_attestation(
            rng,
            subject,
            &Self::to_inner_attestation(attestation),
            strategy,
        )
    }

    fn verify_attestations<R, D, I>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestations: I,
        strategy: &impl commonware_parallel::Strategy,
    ) -> Verification<Self>
    where
        R: rand_core::CryptoRngCore,
        D: commonware_cryptography::Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
    {
        let verification = self.inner.verify_attestations(
            rng,
            subject,
            attestations.into_iter().map(|attestation| Attestation {
                signer: attestation.signer,
                signature: attestation.signature,
            }),
            strategy,
        );

        Verification::new(
            verification
                .verified
                .into_iter()
                .map(Self::from_inner_attestation)
                .collect(),
            verification.invalid,
        )
    }

    fn assemble<I, M>(
        &self,
        attestations: I,
        strategy: &impl commonware_parallel::Strategy,
    ) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
        M: Faults,
    {
        self.inner.assemble::<_, M>(
            attestations.into_iter().map(|attestation| Attestation {
                signer: attestation.signer,
                signature: attestation.signature,
            }),
            strategy,
        )
    }

    fn verify_certificate<R, D, M>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl commonware_parallel::Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRngCore,
        D: commonware_cryptography::Digest,
        M: Faults,
    {
        self.inner
            .verify_certificate::<_, _, M>(rng, subject, certificate, strategy)
    }

    fn is_attributable() -> bool {
        S::is_attributable()
    }

    fn is_batchable() -> bool {
        S::is_batchable()
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as commonware_codec::Read>::Cfg {
        self.inner.certificate_codec_config()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg {
        S::certificate_codec_config_unbounded()
    }
}
