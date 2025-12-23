use crate::{types::Epoch, Supervisor as S, ThresholdSupervisor as TS};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, sharing::Sharing, variant::Variant},
    PublicKey,
};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Supervisor<P: PublicKey, V: Variant> {
    identity: V::Public,
    shares: HashMap<Epoch, Share>,
    polynomials: HashMap<Epoch, Sharing<V>>,
    validators: HashMap<Epoch, Vec<P>>,
    validators_maps: HashMap<Epoch, HashMap<P, u32>>,
}

impl<P: PublicKey, V: Variant> Supervisor<P, V> {
    pub fn new(identity: V::Public) -> Self {
        Self {
            identity,
            shares: HashMap::new(),
            polynomials: HashMap::new(),
            validators: HashMap::new(),
            validators_maps: HashMap::new(),
        }
    }
}

impl<P: PublicKey, V: Variant> Supervisor<P, V> {
    pub fn add_epoch(
        &mut self,
        epoch: Epoch,
        share: Share,
        polynomial: Sharing<V>,
        mut validators: Vec<P>,
    ) {
        // Setup validators
        validators.sort();
        let mut validators_map = HashMap::new();
        for (index, validator) in validators.iter().enumerate() {
            validators_map.insert(validator.clone(), index as u32);
        }

        // Evaluate the polynomial
        let identity = *polynomial.public();
        assert_eq!(identity, self.identity);

        // Store artifacts
        self.shares.insert(epoch, share);
        self.polynomials.insert(epoch, polynomial);
        self.validators.insert(epoch, validators);
        self.validators_maps.insert(epoch, validators_map);
    }
}

impl<P: PublicKey, V: Variant> S for Supervisor<P, V> {
    type Index = Epoch;
    type PublicKey = P;

    fn participants(&self, epoch: Self::Index) -> Option<&[Self::PublicKey]> {
        self.validators.get(&epoch).map(|v| v.as_slice())
    }

    fn is_participant(&self, epoch: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.validators_maps.get(&epoch)?.get(candidate).cloned()
    }
}

impl<P: PublicKey, V: Variant> TS for Supervisor<P, V> {
    type Identity = V::Public;
    type Seed = V::Signature;
    type Polynomial = Sharing<V>;
    type Share = Share;

    fn identity(&self) -> &Self::Identity {
        &self.identity
    }

    fn polynomial(&self, epoch: Self::Index) -> Option<&Self::Polynomial> {
        self.polynomials.get(&epoch)
    }

    fn share(&self, epoch: Self::Index) -> Option<&Self::Share> {
        self.shares.get(&epoch)
    }
}
