use crate::{types::Epoch, Supervisor, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        poly::{public, Public},
        variant::Variant,
    },
    PublicKey,
};
use std::{collections::HashMap, marker::PhantomData};

#[derive(Clone)]
pub struct Validators<P: PublicKey, V: Variant> {
    polynomial: Public<V>,
    validators: Vec<P>,
    validators_map: HashMap<P, u32>,
    share: Option<Share>,

    _phantom: PhantomData<V>,
}

impl<P: PublicKey, V: Variant> Validators<P, V> {
    pub fn new(polynomial: Public<V>, mut validators: Vec<P>, share: Option<Share>) -> Self {
        // Setup validators
        validators.sort();
        let mut validators_map = HashMap::new();
        for (index, validator) in validators.iter().enumerate() {
            validators_map.insert(validator.clone(), index as u32);
        }

        Self {
            polynomial,
            validators,
            validators_map,
            share,

            _phantom: PhantomData,
        }
    }
}

impl<P: PublicKey, V: Variant> Supervisor for Validators<P, V> {
    type Index = Epoch;
    type PublicKey = P;

    fn participants(&self, _: Self::Index) -> Option<&[Self::PublicKey]> {
        Some(&self.validators)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.validators_map.get(candidate).cloned()
    }
}

impl<P: PublicKey, V: Variant> ThresholdSupervisor for Validators<P, V> {
    type Polynomial = Public<V>;
    type Identity = V::Public;
    type Share = Share;
    type Seed = V::Signature;

    fn identity(&self) -> &Self::Identity {
        public::<V>(&self.polynomial)
    }

    fn polynomial(&self, _: Self::Index) -> Option<&Self::Polynomial> {
        Some(&self.polynomial)
    }

    fn share(&self, _: Self::Index) -> Option<&Self::Share> {
        self.share.as_ref()
    }
}
