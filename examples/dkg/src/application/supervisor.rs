//! [commonware_consensus::Supervisor] implementation.

use commonware_consensus::{
    marshal::SigningSchemeProvider,
    threshold_simplex::signing_scheme::ed25519::Scheme,
    types::{Epoch, View},
};
use commonware_cryptography::{ed25519, Signer};
use commonware_resolver::p2p;
use std::collections::HashMap;

/// Implementation of [commonware_consensus::Supervisor] for a static set of participants.
#[derive(Clone)]
pub struct Supervisor<C: Signer> {
    signer: C,
    participants: Vec<C::PublicKey>,
    participants_map: HashMap<C::PublicKey, u32>,
}

impl<C: Signer> Supervisor<C> {
    /// Create a new [Supervisor].
    pub fn new(signer: C, mut participants: Vec<C::PublicKey>) -> Self {
        participants.sort();
        let mut participants_map = HashMap::new();
        for (index, validator) in participants.iter().enumerate() {
            participants_map.insert(validator.clone(), index as u32);
        }

        Self {
            signer,
            participants,
            participants_map,
        }
    }
}

impl<C: Signer> commonware_consensus::Supervisor for Supervisor<C> {
    type Index = View;
    type PublicKey = C::PublicKey;

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

impl SigningSchemeProvider<Scheme> for Supervisor<ed25519::PrivateKey> {
    fn for_epoch(&self, _: Epoch) -> Option<Scheme> {
        Some(Scheme::new(self.participants.clone(), self.signer.clone()))
    }
}

// TODO: Decouple coordinator.
impl<C: Signer> p2p::Coordinator for Supervisor<C> {
    type PublicKey = C::PublicKey;

    fn peers(&self) -> &Vec<Self::PublicKey> {
        &self.participants
    }

    fn peer_set_id(&self) -> u64 {
        // In this example, we only have one static peer set.
        0
    }
}
