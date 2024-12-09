use commonware_consensus::{
    simplex::{
        Prover, View, CONFLICTING_FINALIZE, CONFLICTING_NOTARIZE, FINALIZE, NOTARIZE,
        NULLIFY_AND_FINALIZE,
    },
    Activity, Proof, Supervisor as Su,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use std::collections::{HashMap, HashSet};
use tracing::debug;

#[derive(Clone)]
pub struct Supervisor<C: Scheme, H: Hasher> {
    prover: Prover<C, H>,

    participants: Vec<PublicKey>,
    participants_map: HashMap<PublicKey, u32>,
}

impl<C: Scheme, H: Hasher> Supervisor<C, H> {
    pub fn new(prover: Prover<C, H>, mut participants: Vec<PublicKey>) -> Self {
        // Setup participants
        participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }

        // Return supervisor
        Self {
            prover,

            participants,
            participants_map,
        }
    }
}

impl<C: Scheme, H: Hasher> Su for Supervisor<C, H> {
    type Index = View;
    type Seed = ();

    fn leader(&self, index: Self::Index, _: Self::Seed) -> Option<PublicKey> {
        Some(self.participants[index as usize % self.participants.len()].clone())
    }

    fn participants(&self, _: Self::Index) -> Option<&Vec<PublicKey>> {
        Some(&self.participants)
    }

    fn is_participant(&self, _: Self::Index, candidate: &PublicKey) -> Option<u32> {
        self.participants_map.get(candidate).cloned()
    }

    async fn report(&self, activity: Activity, proof: Proof) {
        match activity {
            NOTARIZE => {
                let (view, _, payload, public_key) =
                    self.prover.deserialize_notarize(proof, false).unwrap();
                debug!(view, "notarize");
            }
            FINALIZE => {
                let (view, _, payload, public_key) =
                    self.prover.deserialize_finalize(proof, false).unwrap();
                debug!(view, "finalize");
            }
            CONFLICTING_NOTARIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_conflicting_notarize(proof, false)
                    .unwrap();
                debug!(view, "conflicting notarize");
            }
            CONFLICTING_FINALIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_conflicting_finalize(proof, false)
                    .unwrap();
                debug!(view, "conflicting finalize");
            }
            NULLIFY_AND_FINALIZE => {
                let (public_key, view) = self
                    .prover
                    .deserialize_nullify_finalize(proof, false)
                    .unwrap();
                debug!(view, "nullify and finalize");
            }
            unexpected => {
                panic!("unexpected activity: {}", unexpected);
            }
        }
    }
}
