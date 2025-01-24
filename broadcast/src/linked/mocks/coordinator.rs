use crate::{linked::Index, Coordinator as S, ThresholdCoordinator as T};
use std::collections::HashMap;

use commonware_cryptography::{
    bls12381::primitives::{
        group::{Public, Share},
        poly::Poly,
    },
    PublicKey,
};

/// Implementation of `commonware-consensus::Coordinator`.
#[derive(Clone)]
pub struct Coordinator {
    identity: Poly<Public>,
    signers: Vec<PublicKey>,
    signers_map: HashMap<PublicKey, u32>,

    share: Share,
}

impl Coordinator {
    pub fn new(identity: Poly<Public>, mut signers: Vec<PublicKey>, share: Share) -> Self {
        // Setup signers
        signers.sort();
        let mut signers_map = HashMap::new();
        for (index, validator) in signers.iter().enumerate() {
            signers_map.insert(validator.clone(), index as u32);
        }

        // Return coordinator
        Self {
            identity,
            signers,
            signers_map,
            share,
        }
    }
}

impl S for Coordinator {
    type Index = Index;

    fn signers(&self, _: Self::Index) -> Option<&Vec<PublicKey>> {
        Some(&self.signers)
    }

    fn is_signer(&self, _: Self::Index, candidate: &PublicKey) -> Option<u32> {
        self.signers_map.get(candidate).cloned()
    }

    fn sequencers(&self, _: Self::Index) -> Option<&Vec<PublicKey>> {
        Some(&self.signers)
    }

    fn is_sequencer(&self, _: Self::Index, candidate: &PublicKey) -> Option<u32> {
        self.signers_map.get(candidate).cloned()
    }
}

impl T for Coordinator {
    type Identity = Poly<Public>;
    type Share = Share;

    fn identity(&self, _: Self::Index) -> Option<&Self::Identity> {
        Some(&self.identity)
    }

    fn share(&self, _: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}
