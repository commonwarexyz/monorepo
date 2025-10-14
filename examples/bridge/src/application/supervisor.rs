use commonware_codec::Encode;
use commonware_consensus::{types::View, Supervisor as Su, ThresholdSupervisor as TSu};
use commonware_cryptography::{
    bls12381::{
        dkg::ops::evaluate_all,
        primitives::{
            group,
            poly::{self, Public},
            variant::{MinSig, Variant},
        },
    },
    PublicKey,
};
use commonware_utils::{modulo, set::Set};

/// Implementation of `commonware-consensus::Supervisor`.
#[derive(Clone)]
pub struct Supervisor<P: PublicKey> {
    identity: <MinSig as Variant>::Public,
    polynomial: Vec<<MinSig as Variant>::Public>,
    participants: Set<P>,

    share: group::Share,
}

impl<P: PublicKey> Supervisor<P> {
    pub fn new(polynomial: Public<MinSig>, participants: Vec<P>, share: group::Share) -> Self {
        // Setup participants
        let identity = *poly::public::<MinSig>(&polynomial);
        let polynomial = evaluate_all::<MinSig>(&polynomial, participants.len() as u32);

        // Return supervisor
        Self {
            identity,
            polynomial,
            participants: Set::from_iter(participants),
            share,
        }
    }
}

impl<P: PublicKey> Su for Supervisor<P> {
    type Index = View;
    type PublicKey = P;

    fn leader(&self, _: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!("only defined in supertrait")
    }

    fn participants(&self, _: Self::Index) -> Option<&[Self::PublicKey]> {
        Some(self.participants.as_ref())
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.participants
            .binary_search(candidate)
            .ok()
            .map(|i| i as u32)
    }
}

impl<P: PublicKey> TSu for Supervisor<P> {
    type Seed = <MinSig as Variant>::Signature;
    type Polynomial = Vec<<MinSig as Variant>::Public>;
    type Share = group::Share;
    type Identity = <MinSig as Variant>::Public;

    fn leader(&self, _: Self::Index, seed: Self::Seed) -> Option<Self::PublicKey> {
        let seed = seed.encode();
        let index = modulo(&seed, self.participants.len() as u64);
        Some(self.participants[index as usize].clone())
    }

    fn identity(&self) -> &Self::Identity {
        &self.identity
    }

    fn polynomial(&self, _: Self::Index) -> Option<&Self::Polynomial> {
        Some(&self.polynomial)
    }

    fn share(&self, _: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}
