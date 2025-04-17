use commonware_consensus::{
    simplex::types::{Activity, View, Viewable},
    Reporter, Supervisor as Su,
};
use commonware_cryptography::Digest;
use commonware_utils::Array;
use std::{collections::HashMap, marker::PhantomData};
use tracing::info;

/// Implementation of `commonware-consensus::Supervisor`.
#[derive(Clone)]
pub struct Supervisor<P: Array, S: Array, D: Digest> {
    participants: Vec<P>,
    participants_map: HashMap<P, u32>,

    _phantom_s: PhantomData<S>,
    _phantom_d: PhantomData<D>,
}

impl<P: Array, S: Array, D: Digest> Supervisor<P, S, D> {
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

            _phantom_s: PhantomData,
            _phantom_d: PhantomData,
        }
    }
}

impl<P: Array, S: Array, D: Digest> Su for Supervisor<P, S, D> {
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

impl<P: Array, S: Array, D: Digest> Reporter for Supervisor<P, S, D> {
    type Activity = Activity<S, D>;

    async fn report(&mut self, activity: Activity<S, D>) {
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
