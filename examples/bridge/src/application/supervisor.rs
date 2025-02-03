use commonware_consensus::{
    threshold_simplex::View, Activity, Proof, Supervisor as Su, ThresholdSupervisor as TSu,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        poly::{self, Poly},
    },
    PublicKey,
};
use commonware_utils::modulo;
use std::collections::HashMap;

/// Implementation of `commonware-consensus::Supervisor`.
#[derive(Clone)]
pub struct Supervisor<P: PublicKey> {
    identity: Poly<group::Public>,
    participants: Vec<P>,
    participants_map: HashMap<P, u32>,

    share: group::Share,
}

impl<P: PublicKey> Supervisor<P> {
    pub fn new(
        identity: Poly<group::Public>,
        mut participants: Vec<P>,
        share: group::Share,
    ) -> Self {
        // Setup participants
        participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(*validator, index as u32);
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

    async fn report(&self, _: Activity, _: Proof) {
        // We don't report activity in this example but you would otherwise use
        // this to collect uptime and fraud proofs.
    }
}

impl<P: PublicKey> TSu for Supervisor<P> {
    type Seed = group::Signature;
    type Identity = poly::Public;
    type Share = group::Share;

    fn leader(&self, _: Self::Index, seed: Self::Seed) -> Option<Self::PublicKey> {
        let seed = seed.serialize();
        let index = modulo(&seed, self.participants.len() as u64);
        Some(self.participants[index as usize])
    }

    fn identity(&self, _: Self::Index) -> Option<&Self::Identity> {
        Some(&self.identity)
    }

    fn share(&self, _: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}
