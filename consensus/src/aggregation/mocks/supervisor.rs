use crate::{aggregation::types::Epoch, Supervisor as S, ThresholdSupervisor as TS};
use commonware_cryptography::{
    bls12381::{
        dkg::ops::evaluate_all,
        primitives::{group::Share, poly, variant::Variant},
    },
    PublicKey,
};
use std::{collections::HashMap, marker::PhantomData};

#[derive(Clone)]
pub struct Supervisor<P: PublicKey, V: Variant> {
    shares: HashMap<Epoch, Share>,
    polynomials: HashMap<Epoch, (V::Public, Vec<V::Public>)>,
    validators: HashMap<Epoch, Vec<P>>,
    validators_maps: HashMap<Epoch, HashMap<P, u32>>,
    _phantom: PhantomData<(P, V)>,
}

impl<P: PublicKey, V: Variant> Default for Supervisor<P, V> {
    fn default() -> Self {
        Self {
            shares: HashMap::new(),
            polynomials: HashMap::new(),
            validators: HashMap::new(),
            validators_maps: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

impl<P: PublicKey, V: Variant> Supervisor<P, V> {
    pub fn add_epoch(
        &mut self,
        epoch: Epoch,
        share: Share,
        polynomial: poly::Public<V>,
        mut validators: Vec<P>,
    ) {
        // Setup validators
        validators.sort();
        let mut validators_map = HashMap::new();
        for (index, validator) in validators.iter().enumerate() {
            validators_map.insert(validator.clone(), index as u32);
        }

        // Evaluate the polynomial
        let identity = *poly::public::<V>(&polynomial);
        let polynomial = evaluate_all::<V>(&polynomial, validators.len() as u32);

        self.shares.insert(epoch, share);
        self.polynomials.insert(epoch, (identity, polynomial));
        self.validators.insert(epoch, validators);
        self.validators_maps.insert(epoch, validators_map);
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
    type Identity = V::Public;
    type Seed = V::Signature;
    type Polynomial = Vec<V::Public>;
    type Share = Share;

    fn identity(&self) -> &Self::Identity {
        // Return the identity from the first available polynomial
        let next = self
            .polynomials
            .values()
            .next()
            .expect("No polynomials available");
        &next.0
    }

    fn leader(&self, _: Self::Index, _: Self::Seed) -> Option<Self::PublicKey> {
        unimplemented!()
    }

    fn polynomial(&self, epoch: Self::Index) -> Option<&Self::Polynomial> {
        self.polynomials
            .get(&epoch)
            .map(|(_, polynomial)| polynomial)
    }

    fn share(&self, epoch: Self::Index) -> Option<&Self::Share> {
        self.shares.get(&epoch)
    }
}
