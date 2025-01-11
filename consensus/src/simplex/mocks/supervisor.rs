use crate::{simplex::View, Activity, Proof, Supervisor as Su, ThresholdSupervisor as TSu};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        poly,
    },
    PublicKey,
};
use std::collections::{BTreeMap, HashMap};

type ViewInfo = (
    poly::Poly<group::Public>,
    HashMap<PublicKey, u32>,
    Vec<PublicKey>,
    group::Share,
);

pub struct Config {
    pub participants: BTreeMap<View, (poly::Poly<group::Public>, Vec<PublicKey>, group::Share)>,
}

#[derive(Clone)]
pub struct Supervisor {
    participants: BTreeMap<View, ViewInfo>,
}

impl Supervisor {
    pub fn new(cfg: Config) -> Self {
        let mut parsed_participants = BTreeMap::new();
        for (view, (identity, mut validators, share)) in cfg.participants.into_iter() {
            let mut map = HashMap::new();
            for (index, validator) in validators.iter().enumerate() {
                map.insert(validator.clone(), index as u32);
            }
            validators.sort();
            parsed_participants.insert(view, (identity, map, validators, share));
        }
        Self {
            participants: parsed_participants,
        }
    }
}

impl Su for Supervisor {
    type Index = View;

    fn leader(&self, _: Self::Index) -> Option<PublicKey> {
        unimplemented!("only defined in supertrait")
    }

    fn participants(&self, index: Self::Index) -> Option<&Vec<PublicKey>> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, _, p, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest)
    }

    fn is_participant(&self, index: Self::Index, candidate: &PublicKey) -> Option<u32> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, p, _, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        closest.get(candidate).cloned()
    }

    async fn report(&self, _: Activity, _: Proof) {}
}

impl TSu for Supervisor {
    type Seed = group::Signature;
    type Identity = poly::Public;
    type Share = group::Share;

    fn leader(&self, seed: Self::Seed, index: Self::Index) -> Option<PublicKey> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, _, p, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        let seed = seed.serialize();
        let modulo = u64::from_be_bytes(seed[0..8].try_into().unwrap());
        let index = modulo % closest.len() as u64;
        Some(closest[index as usize].clone())
    }

    fn identity(&self, index: Self::Index) -> Option<&Self::Identity> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (p, _, _, _))) => p,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest)
    }

    fn share(&self, index: Self::Index) -> Option<&Self::Share> {
        let closest = match self.participants.range(..=index).next_back() {
            Some((_, (_, _, _, s))) => s,
            None => {
                panic!("no participants in required range");
            }
        };
        Some(closest)
    }
}
