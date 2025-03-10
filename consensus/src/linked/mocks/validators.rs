use super::super::Epoch;
use crate::{Supervisor, ThresholdSupervisor};
use commonware_cryptography::bls12381::primitives::{
    group::{self, Public, Share},
    poly::Poly,
};
use commonware_utils::Array;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Validators<P: Array> {
    identity: Poly<Public>,
    validators: Vec<P>,
    validators_map: HashMap<P, u32>,
    share: Share,
}

impl<P: Array> Validators<P> {
    pub fn new(identity: Poly<Public>, mut validators: Vec<P>, share: Share) -> Self {
        // Setup validators
        validators.sort();
        let mut validators_map = HashMap::new();
        for (index, validator) in validators.iter().enumerate() {
            validators_map.insert(validator.clone(), index as u32);
        }

        Self {
            identity,
            validators,
            validators_map,
            share,
        }
    }
}

impl<P: Array> Supervisor for Validators<P> {
    type Index = Epoch;
    type PublicKey = P;

    fn leader(&self, _: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!()
    }

    async fn report(&self, _: crate::Activity, _: crate::Proof) {
        unimplemented!()
    }

    fn participants(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.validators)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.validators_map.get(candidate).cloned()
    }
}

impl<P: Array> ThresholdSupervisor for Validators<P> {
    type Identity = Poly<Public>;
    type Share = Share;
    type Seed = group::Signature;

    fn leader(&self, _: Self::Index, _: Self::Seed) -> Option<Self::PublicKey> {
        unimplemented!()
    }

    fn identity(&self, _: Self::Index) -> Option<&Self::Identity> {
        Some(&self.identity)
    }

    fn share(&self, _: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}
