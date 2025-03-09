use super::super::Epoch;
use crate::{Coordinator as S, Supervisor, ThresholdSupervisor};
use commonware_cryptography::bls12381::primitives::{
    group::{self, Public, Share},
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

impl<P: Array> Supervisor for Coordinator<P> {
    type Index = Epoch;
    type PublicKey = P;

    fn leader(&self, _: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!()
    }

    async fn report(&self, _: crate::Activity, _: crate::Proof) {
        unimplemented!()
    }

    fn participants(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.signers)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.signers_map.get(candidate).cloned()
    }
}

impl<P: Array> ThresholdSupervisor for Coordinator<P> {
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

impl<P: Array> S for Coordinator<P> {
    fn index(&self) -> Self::Index {
        self.view
    }

    fn sequencers(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.signers)
    }

    fn is_sequencer(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.signers_map.get(candidate).cloned()
    }
}
