use commonware_consensus::{
    simplex::types::{Activity, View},
    Reporter, Supervisor as Su,
};
use commonware_cryptography::Digest;
use commonware_utils::Array;
use std::{collections::HashMap, marker::PhantomData};

/// Implementation of `commonware-consensus::Supervisor`.
#[derive(Clone)]
pub struct Supervisor<P: Array, D: Digest> {
    participants: Vec<P>,
    participants_map: HashMap<P, u32>,

    _phantom: PhantomData<D>,
}

impl<P: Array, D: Digest> Supervisor<P, D> {
    pub fn new(mut participants: Vec<P>) -> Self {
        // Setup participants
        participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }

        // Return supervisor
        Self {
            participants,
            participants_map,

            _phantom: PhantomData,
        }
    }
}

impl<P: Array, D: Digest> Su for Supervisor<P, D> {
    type Index = View;
    type PublicKey = P;

    fn leader(&self, index: Self::Index) -> Option<Self::PublicKey> {
        Some(self.participants[index as usize % self.participants.len()].clone())
    }

    fn participants(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.participants)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.participants_map.get(candidate).cloned()
    }
}

impl<P: Array, D: Digest> Reporter for Supervisor<P, D> {
    type Activity = Activity<P, D>;

    async fn report(&mut self, _: Activity<P, D>) {
        // We don't report activity in this example but you would otherwise use
        // this to collect uptime and fraud proofs.
    }
}
