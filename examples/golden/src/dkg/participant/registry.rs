use crate::dkg::broadcast::BroadcastMsg;
use crate::dkg::participant::evrf::EVRF;
use crate::error::Error;
use commonware_cryptography::bls12381::primitives::group::Element;
use commonware_cryptography::bls12381::primitives::group::Scalar;
use commonware_cryptography::bls12381::primitives::group::G1;
use commonware_cryptography::bls12381::PublicKey;
use commonware_utils::set::Ordered;
use std::collections::{HashMap, HashSet};
use thiserror::Error as ThisError;
use tracing::debug;

#[derive(Debug, ThisError)]
pub enum RegistryError {
    #[error("Share not found for player {0}")]
    ShareNotFound(u32),
    #[error("Index not found for player {0}")]
    IndexNotFound(Box<PublicKey>),
}

/// Short-lived registry: re-initied at every round
#[derive(Clone)]
pub struct Registry {
    dealer_broadcasted: HashSet<u32>,
    pubkey_shares: HashMap<u32, G1>,
    share: Scalar,
    group_pubkey: G1,
    ready: bool,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            dealer_broadcasted: Default::default(),
            pubkey_shares: Default::default(),
            share: Scalar::zero(),
            group_pubkey: G1::zero(),
            ready: false,
        }
    }
}

impl Registry {
    // Steps (11), ..., (16)
    pub fn on_incoming_bmsg(
        &mut self,
        dealer_pk: &PublicKey,
        player_id: u32,
        mut bmsg: BroadcastMsg,
        players: &Ordered<PublicKey>,
        evrf: &EVRF,
    ) -> Result<(), Error> {
        // Decrypt f_{j}(i) and store it
        let Some(dealer) = players.position(dealer_pk) else {
            return Err(RegistryError::IndexNotFound(Box::new(dealer_pk.clone())).into());
        };
        let dealer = dealer as u32;

        if !self.dealer_broadcasted.insert(dealer) {
            return Ok(());
        }
        let share_commitments = bmsg.validate(dealer, players)?;
        let Some(my_share) = bmsg.take_ciphered_share(player_id) else {
            return Err(RegistryError::ShareNotFound(player_id).into());
        };
        self.update_share_commitments(share_commitments);

        let evrf_output = evrf.evaluate(bmsg.msg(), dealer_pk);

        debug!(target:"player", dealer_pk=dealer_pk.to_string(),dealer_id=dealer, "Recovered secret scalar: {}",evrf_output.scalar);

        let decrypted = my_share.decrypt(evrf_output.scalar)?;

        self.share.add(&decrypted);

        // Update the group public key
        let a0 = bmsg.commitment_omega();
        self.group_pubkey.add(&a0);

        let n = players.len();

        if self.dealer_broadcasted.len() == n {
            self.ready = true
        }

        Ok(())
    }

    pub fn get_share(&self) -> Option<&Scalar> {
        if !self.ready {
            return None;
        }
        Some(&self.share)
    }

    pub fn get_group_pubkey(&self) -> Option<PublicKey> {
        if !self.ready {
            return None;
        }
        Some(PublicKey::from(self.group_pubkey))
    }

    pub fn pubkey_share(&self, k: u32) -> Option<PublicKey> {
        if !self.ready {
            return None;
        }
        self.pubkey_shares.get(&k).map(|x| PublicKey::from(*x))
    }

    pub fn pubkey_shares(&self) -> Option<&HashMap<u32, G1>> {
        if !self.ready {
            return None;
        }
        Some(&self.pubkey_shares)
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    fn update_share_commitments(&mut self, share_commitments: Vec<(u32, G1)>) {
        for (player, share_commitment) in share_commitments {
            let entry = self.pubkey_shares.entry(player).or_insert(G1::zero());

            entry.add(&share_commitment);
        }
    }
}
