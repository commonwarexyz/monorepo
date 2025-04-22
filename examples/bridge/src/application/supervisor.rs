use commonware_codec::Encode;
use commonware_consensus::{
    threshold_simplex::types::View, Supervisor as Su, ThresholdSupervisor as TSu,
};
use commonware_cryptography::bls12381::primitives::{
    group,
    poly::{self, Poly},
};
use commonware_utils::{modulo, Array};
use std::collections::HashMap;

/// Implementation of `commonware-consensus::Supervisor`.
#[derive(Clone)]
pub struct Supervisor<P: Array> {
    identity: Poly<group::Public>,
    participants: Vec<P>,
    participants_map: HashMap<P, u32>,

    share: group::Share,
}

impl<P: Array> Supervisor<P> {
    pub fn new(
        identity: Poly<group::Public>,
        mut participants: Vec<P>,
        share: group::Share,
    ) -> Self {
        // Setup participants
        participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }

        // Return supervisor
        Self {
            identity,
            participants,
            participants_map,
            share,
        }
    }
}

impl<P: Array> Su for Supervisor<P> {
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

impl<P: Array> TSu for Supervisor<P> {
    type Seed = group::Signature;
    type Identity = poly::Public;
    type Share = group::Share;

    fn leader(&self, _: Self::Index, seed: Self::Seed) -> Option<Self::PublicKey> {
        let seed = seed.encode();
        let index = modulo(&seed, self.participants.len() as u64);
        Some(self.participants[index as usize].clone())
    }

    fn identity(&self, _: Self::Index) -> Option<&Self::Identity> {
        Some(&self.identity)
    }

    fn share(&self, _: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}
