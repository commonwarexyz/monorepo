use commonware_consensus::{
    simplex::types::{Activity, View, Viewable},
    Reporter, Supervisor as Su,
};
use commonware_cryptography::{Digest, Specification};
use std::{collections::HashMap, marker::PhantomData};
use tracing::info;

/// Implementation of `commonware-consensus::Supervisor`.
#[derive(Clone)]
pub struct Supervisor<S: Specification, D: Digest> {
    participants: Vec<S::PublicKey>,
    participants_map: HashMap<S::PublicKey, u32>,

    _phantom: PhantomData<D>,
}

impl<S: Specification, D: Digest> Supervisor<S, D> {
    pub fn new(mut participants: Vec<S::PublicKey>) -> Self {
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

impl<S: Specification, D: Digest> Su for Supervisor<S, D> {
    type Index = View;
    type PublicKey = S::PublicKey;

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

impl<S: Specification, D: Digest> Reporter for Supervisor<S, D> {
    type Activity = Activity<S::Signature, D>;

    async fn report(&mut self, activity: Activity<S::Signature, D>) {
        let view = activity.view();
        match activity {
            Activity::Notarization(notarization) => {
                info!(view, payload = ?notarization.proposal.payload, "notarized");
            }
            Activity::Finalization(finalization) => {
                info!(view, payload = ?finalization.proposal.payload, "finalized");
            }
            Activity::Nullification(_) => {
                info!(view, "nullified");
            }
            _ => {}
        }
    }
}
