use commonware_codec::Encode;
use commonware_consensus::{types::View, Supervisor as Su, ThresholdSupervisor as TSu};
use commonware_cryptography::{
    bls12381::{
        dkg::ops::evaluate_all,
        primitives::{
            group, poly,
            variant::{MinSig, Variant},
        },
    },
    PublicKey,
};
use commonware_utils::modulo;
use std::collections::HashMap;

/// Implementation of `commonware-consensus::Supervisor`.
#[derive(Clone)]
pub struct Supervisor<P: PublicKey> {
    identity: <MinSig as Variant>::Public,
    polynomial: Vec<<MinSig as Variant>::Public>,
    participants: Vec<P>,
    participants_map: HashMap<P, u32>,
    share: Option<group::Share>,
}

impl<P: PublicKey> Supervisor<P> {
    pub fn new(
        polynomial: poly::Public<MinSig>,
        mut participants: Vec<P>,
        share: Option<group::Share>,
    ) -> Self {
        // Setup participants
        participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }
        let identity = *poly::public::<MinSig>(&polynomial);
        let polynomial = evaluate_all::<MinSig>(&polynomial, participants.len() as u32);

        // Return supervisor
        Self {
            identity,
            polynomial,
            participants,
            participants_map,
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

    fn participants(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.participants)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.participants_map.get(candidate).cloned()
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
        self.share.as_ref()
    }
}
