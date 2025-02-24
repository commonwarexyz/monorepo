use commonware_consensus::{simplex::View, Activity, Proof, Supervisor as Su};
use commonware_utils::Array;
use std::collections::HashMap;

/// Implementation of `commonware-consensus::Supervisor`.
#[derive(Clone)]
pub struct Supervisor<P: Array> {
    participants: Vec<P>,
    participants_map: HashMap<P, u32>,
}

impl<P: Array> Supervisor<P> {
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
        }
    }
}

impl<P: Array> Su for Supervisor<P> {
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

    async fn report(&self, _: Activity, _: Proof) {
        // We don't report activity in this example but you would otherwise use
        // this to collect uptime and fraud proofs.
    }
}
