//! [commonware_consensus::Supervisor] implementation.

use commonware_codec::Encode;
use commonware_consensus::{types::View, ThresholdSupervisor};
use commonware_cryptography::{
    bls12381::{
        dkg::ops::evaluate_all,
        primitives::{
            group,
            poly::{self, Poly},
            variant::Variant,
        },
    },
    PublicKey,
};
use commonware_resolver::p2p;
use commonware_utils::modulo;
use std::collections::HashMap;

/// Implementation of [commonware_consensus::Supervisor] for a static set of participants.
#[derive(Clone)]
pub struct Supervisor<V: Variant, P: PublicKey> {
    identity: V::Public,
    polynomial: Vec<V::Public>,
    participants: Vec<P>,
    participants_map: HashMap<P, u32>,

    share: group::Share,
}

impl<V: Variant, P: PublicKey> Supervisor<V, P> {
    /// Create a new [Supervisor].
    pub fn new(polynomial: Poly<V::Public>, mut participants: Vec<P>, share: group::Share) -> Self {
        participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }
        let identity = *poly::public::<V>(&polynomial);
        let polynomial = evaluate_all::<V>(&polynomial, participants.len() as u32);

        Self {
            identity,
            polynomial,
            participants,
            participants_map,
            share,
        }
    }
}

impl<V: Variant, P: PublicKey> p2p::Coordinator for Supervisor<V, P> {
    type PublicKey = P;

    fn peers(&self) -> &Vec<Self::PublicKey> {
        &self.participants
    }

    fn peer_set_id(&self) -> u64 {
        0
    }
}

impl<V: Variant, P: PublicKey> commonware_consensus::Supervisor for Supervisor<V, P> {
    type Index = View;
    type PublicKey = P;

    fn leader(&self, _: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!("only defined in threshold supervisor")
    }

    fn participants(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.participants)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.participants_map.get(candidate).cloned()
    }
}

impl<V: Variant, P: PublicKey> ThresholdSupervisor for Supervisor<V, P> {
    type Seed = V::Signature;
    type Identity = V::Public;
    type Polynomial = Vec<V::Public>;
    type Share = group::Share;

    fn leader(&self, _: Self::Index, seed: Self::Seed) -> Option<Self::PublicKey> {
        let index = modulo(seed.encode().as_ref(), self.participants.len() as u64) as usize;
        Some(self.participants[index].clone())
    }

    fn identity(&self) -> &Self::Identity {
        &self.identity
    }

    fn polynomial(&self, _: Self::Index) -> Option<&Self::Polynomial> {
        Some(&self.polynomial)
    }

    fn share(&self, _: Self::Index) -> Option<&Self::Share> {
        Some(&self.share)
    }
}
