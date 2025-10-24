use super::*;
use crate::broadcast::BroadcastMsg;
use crate::cyphered_share::CypheredShare;
use crate::error::Error;
use crate::evrf::EVRF;
use commonware_cryptography::bls12381::primitives::group::Element;
use commonware_cryptography::bls12381::primitives::group::Scalar;
use commonware_cryptography::bls12381::primitives::variant::Variant;
use std::collections::{HashMap, HashSet};
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum RegistryError {
    #[error("Dealer already seen: {0}")]
    DealerAlreadySeen(u32),
    #[error("Share not found for player {0}")]
    ShareNotFound(u32),
    #[error("Public key not found for player {0}")]
    PubkeyNotFound(u32),
}

/// Short-lived registry: re-initied at every round
pub struct Registry<V: Variant> {
    player_id: u32,
    dealer_broadcasted: HashSet<u32>,
    player_pubkeys: HashMap<u32, V::Public>,
    share: Scalar,
    group_pubkey: V::Public,
    ready: bool,
}

impl<V: Variant> Registry<V> {
    pub fn new(player_id: u32) -> Self {
        Self {
            player_id,
            dealer_broadcasted: Default::default(),
            player_pubkeys: Default::default(),
            share: Scalar::zero(),
            group_pubkey: V::Public::zero(),
            ready: false,
        }
    }

    // Steps (11), ..., (16)
    pub fn on_incoming_bmsg(
        &mut self,
        dealer: u32,
        mut bmsg: BroadcastMsg<V>,
        participants_pk_i: &HashMap<u32, V::Public>,
        evrf: &EVRF<V>,
    ) -> Result<(), Error> {
        if !self.dealer_broadcasted.insert(dealer) {
            return Err(RegistryError::DealerAlreadySeen(dealer).into());
        }
        let share_commitments = bmsg.validate(dealer, participants_pk_i)?;
        let Some(my_share) = bmsg.take_cyphered_share(self.player_id) else {
            return Err(RegistryError::ShareNotFound(self.player_id).into());
        };
        self.update_share_commitments(share_commitments);

        // Decrypt f_{j}(i) and store it
        let Some(dealer_pk) = participants_pk_i.get(&dealer) else {
            return Err(RegistryError::PubkeyNotFound(dealer).into());
        };
        let evrf_output = evrf.evaluate(bmsg.msg(), *dealer_pk);

        let decrypted = my_share.decrypt(evrf_output.scalar)?;

        self.share.add(&decrypted);

        // Update the group public key
        let a0 = bmsg.commitment_omega();
        self.group_pubkey.add(&a0);

        let n = participants_pk_i.len();

        if self.dealer_broadcasted.len() == n - 1 {
            self.ready = true
        }

        Ok(())
    }

    pub fn share(&self) -> Option<&Scalar> {
        if !self.ready {
            return None;
        }
        Some(&self.share)
    }

    pub fn group_pubkey(&self) -> Option<&V::Public> {
        if !self.ready {
            return None;
        }
        Some(&self.group_pubkey)
    }

    pub fn player_pubkey(&self, k: u32) -> Option<&V::Public> {
        if !self.ready {
            return None;
        }
        self.player_pubkeys.get(&k)
    }

    fn update_share_commitments(&mut self, share_commitments: Vec<(u32, V::Public)>) {
        for (player, share_commitment) in share_commitments {
            let entry = self
                .player_pubkeys
                .entry(player)
                .or_insert(V::Public::zero());

            entry.add(&share_commitment);
        }
    }
}
