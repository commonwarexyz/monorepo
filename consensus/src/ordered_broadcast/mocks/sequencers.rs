use super::super::Epoch;
use crate::Supervisor;
use commonware_utils::Array;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Sequencers<P: Array> {
    participants: Vec<P>,
    participants_map: HashMap<P, u32>,
}

impl<P: Array> Sequencers<P> {
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

impl<P: Array> Supervisor for Sequencers<P> {
    type Index = Epoch;
    type PublicKey = P;

    fn leader(&self, _: Self::Index) -> Option<Self::PublicKey> {
        unimplemented!()
    }

    async fn report(&self, _: crate::Activity, _: crate::Proof) {
        unimplemented!()
    }

    fn participants(&self, _: Self::Index) -> Option<&Vec<Self::PublicKey>> {
        Some(&self.participants)
    }

    fn is_participant(&self, _: Self::Index, candidate: &Self::PublicKey) -> Option<u32> {
        self.participants_map.get(candidate).cloned()
    }
}
