use crate::{aggregation::types::Epoch, Supervisor as S, ThresholdSupervisor as TS};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        poly::{self, Public},
        variant::Variant,
    },
    PublicKey,
};
use std::{collections::HashMap, marker::PhantomData};

#[derive(Clone)]
pub struct Supervisor<P: PublicKey, V: Variant> {
    shares: HashMap<Epoch, Share>,
    polynomials: HashMap<Epoch, Public<V>>,
    validators: HashMap<Epoch, Vec<P>>,
    validators_maps: HashMap<Epoch, HashMap<P, u32>>,
    _phantom: PhantomData<(P, V)>,
}

impl<P: PublicKey, V: Variant> Supervisor<P, V> {
    pub fn new() -> Self {
        Self {
            shares: HashMap::new(),
            polynomials: HashMap::new(),
            validators: HashMap::new(),
            validators_maps: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    pub fn add_epoch(
        &mut self,
        epoch: Epoch,
        share: Share,
        polynomial: Public<V>,
        mut validators: Vec<P>,
    ) {
        // Setup validators
        validators.sort();
        let mut validators_map = HashMap::new();
        for (index, validator) in validators.iter().enumerate() {
            validators_map.insert(validator.clone(), index as u32);
        }

        self.shares.insert(epoch, share);
        self.polynomials.insert(epoch, polynomial);
        self.validators.insert(epoch, validators);
        self.validators_maps.insert(epoch, validators_map);
    }
}

impl<P: PublicKey, V: Variant> Default for Supervisor<P, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PublicKey, V: Variant> S for Supervisor<P, V> {
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

impl<P: PublicKey, V: Variant> TS for Supervisor<P, V> {
    type Identity = poly::Public<V>;
    type Seed = V::Signature;
    type Polynomial = Public<V>;
    type Share = Share;

    fn identity(&self) -> &Self::Identity {
        // Return the identity from the first available polynomial
        self.polynomials
            .values()
            .next()
            .expect("No polynomials available")
    }

    fn leader(&self, _: Self::Index, _: Self::Seed) -> Option<Self::PublicKey> {
        unimplemented!()
    }

    fn polynomial(&self, epoch: Self::Index) -> Option<&Self::Polynomial> {
        self.polynomials.get(&epoch)
    }

    fn share(&self, epoch: Self::Index) -> Option<&Self::Share> {
        self.shares.get(&epoch)
    }
}
