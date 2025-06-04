use crate::{ordered_broadcast::types::Epoch, Supervisor};
use commonware_cryptography::PublicKey;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Sequencers<P: PublicKey> {
    participants: Vec<P>,
    participants_map: HashMap<P, u32>,
}

impl<P: PublicKey> Sequencers<P> {
    pub fn new(mut participants: Vec<P>) -> Self {
        // Setup participants
        participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }

        Self {
            participants,
            participants_map,
        }
    }
}

impl<P: PublicKey> Supervisor for Sequencers<P> {
    type Index = Epoch;
    type PublicKey = P;

    fn leader(&self, _: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!()
    }

    fn participants(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.participants)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.participants_map.get(candidate).cloned()
    }
}
