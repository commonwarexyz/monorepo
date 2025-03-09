use crate::{linked::Epoch, Coordinator as S, ThresholdCoordinator as T};
use commonware_cryptography::bls12381::primitives::{
    group::{Public, Share},
    poly::Poly,
};
use commonware_utils::Array;
use std::collections::HashMap;

/// Implementation of `commonware-consensus::Coordinator`.
#[derive(Clone)]
pub struct Coordinator<P: Array> {
    view: u64,
    identity: Poly<Public>,
    signers: Vec<P>,
    signers_map: HashMap<P, u32>,
    share: Share,
}

impl<P: Array> Coordinator<P> {
    pub fn new(identity: Poly<Public>, mut signers: Vec<P>, share: Share) -> Self {
        // Setup signers
        signers.sort();
        let mut signers_map = HashMap::new();
        for (index, validator) in signers.iter().enumerate() {
            signers_map.insert(validator.clone(), index as u32);
        }

        // Return coordinator
        Self {
            view: 0,
            identity,
            signers,
            signers_map,
            share,
        }
    }

    pub fn set_view(&mut self, view: u64) {
        self.view = view;
    }
}

impl<P: Array> S for Coordinator<P> {
    type Index = Epoch;
    type PublicKey = P;

    fn index(&self) -> Self::Index {
        self.view
    }

    fn signers(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.signers)
    }

    fn is_signer(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.signers_map.get(candidate).cloned()
    }

    fn sequencers(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.signers)
    }

    fn is_sequencer(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.signers_map.get(candidate).cloned()
    }
}

impl<P: Array> T for Coordinator<P> {
    type Identity = Poly<Public>;
    type Share = Share;

    fn identity(&self, _: Self::Index) -> Option<&Self::Identity> {
        Some(&self.identity)
    }

    fn share(&self, _: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}
