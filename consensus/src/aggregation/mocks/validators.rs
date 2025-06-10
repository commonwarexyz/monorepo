use crate::{aggregation::types::Epoch, Supervisor, ThresholdSupervisor};
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
    polynomials: HashMap<Epoch, Public<V>>,
    validators: HashMap<Epoch, Vec<P>>,
    validators_maps: HashMap<Epoch, HashMap<P, u32>>,
    shares: HashMap<Epoch, Share>,

    _phantom: PhantomData<V>,
}

impl<P: PublicKey, V: Variant> Validators<P, V> {
    pub fn new() -> Self {
        Self {
            polynomials: HashMap::new(),
            validators: HashMap::new(),
            validators_maps: HashMap::new(),
            shares: HashMap::new(),

            _phantom: PhantomData,
        }
    }

    pub fn add_epoch(
        &mut self,
        epoch: Epoch,
        polynomial: Public<V>,
        mut validators: Vec<P>,
        share: Share,
    ) {
        // Setup validators
        validators.sort();
        let mut validators_map = HashMap::new();
        for (index, validator) in validators.iter().enumerate() {
            validators_map.insert(validator.clone(), index as u32);
        }

        self.polynomials.insert(epoch, polynomial);
        self.validators.insert(epoch, validators);
        self.validators_maps.insert(epoch, validators_map);
        self.shares.insert(epoch, share);
    }
}

impl<P: PublicKey, V: Variant> Default for Validators<P, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PublicKey, V: Variant> Supervisor for Validators<P, V> {
    type Index = Epoch;
    type PublicKey = P;

    fn leader(&self, _: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!()
    }

    fn participants(&self, epoch: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        self.validators.get(&epoch)
    }

    fn is_participant(&self, epoch: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.validators_maps.get(&epoch)?.get(candidate).cloned()
    }
}

impl<P: PublicKey, V: Variant> ThresholdSupervisor for Validators<P, V> {
    type Polynomial = Public<V>;
    type Identity = V::Public;
    type Share = Share;
    type Seed = V::Signature;

    fn leader(&self, _: Self::Index, _: Self::Seed) -> Option<Self::PublicKey> {
        unimplemented!()
    }

    fn identity(&self) -> &Self::Identity {
        // Return the identity from the first available polynomial
        // In practice, this would be managed more carefully
        let first_polynomial = self
            .polynomials
            .values()
            .next()
            .expect("No polynomials available");
        public::<V>(first_polynomial)
    }

    fn polynomial(&self, epoch: Self::Index) -> Option<&Self::Polynomial> {
        self.polynomials.get(&epoch)
    }

    fn share(&self, epoch: Self::Index) -> Option<&Self::Share> {
        self.shares.get(&epoch)
    }
}
