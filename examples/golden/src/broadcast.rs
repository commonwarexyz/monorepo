use std::collections::HashMap;

use crate::error::Error;
use crate::share::CypheredShare;
use commonware_cryptography::bls12381::primitives::group::{Element, Scalar};
use commonware_cryptography::bls12381::primitives::{poly, variant::Variant};
use thiserror::Error as ThisError;
#[derive(Debug, ThisError)]
pub enum BroadcastMsgError {
    #[error("Player public key not found {0}")]
    PlayerNotFound(u32),
    #[error("Insufficient amount of shares {0}")]
    InsufficientShares(u32),
    #[error("Invalid cyphertext")]
    InvalidCypherText,
}

struct BroadcastMsg<V: Variant> {
    msg: Vec<u8>,
    shares: Vec<CypheredShare<V>>,
    poly: poly::Public<V>,
}

impl<V: Variant> BroadcastMsg<V> {
    /// Validation to be performeded every time that a player receives a [`BroadcastMsg`] from a dealer
    /// This function covers steps 7-8-9 of Round1
    pub fn validate(
        &self,
        dealer: u32,
        participants: HashMap<u32, V::Public>,
    ) -> Result<(), Error> {
        let Some(dealer_pk) = participants.get(&dealer) else {
            return Err(BroadcastMsgError::PlayerNotFound(dealer).into());
        };
        let num_players = participants.len() as u32;
        let shares_len = self.shares.len() as u32;
        if shares_len < num_players - 1 {
            // dealer doesnt broadcast his own share
            return Err(BroadcastMsgError::InsufficientShares(shares_len).into());
        }

        for cs in &self.shares {
            let k = cs.index();
            if k == dealer {
                continue;
            }
            let Some(receiver_pk) = participants.get(&k) else {
                return Err(BroadcastMsgError::PlayerNotFound(dealer).into());
            };
            cs.verify_zk_proof(*dealer_pk, &self.msg, *receiver_pk)?;

            self.verify_validity_of_cyphertext(cs, k)?;
        }
        Ok(())
    }

    fn verify_validity_of_cyphertext(&self, cs: &CypheredShare<V>, k: u32) -> Result<(), Error> {
        let g_z = cs.commitment_cyphered_share();
        let mut r = cs.commitment_random_scalar();
        let x = self.compute_share_committment(k);
        r.add(&x);

        if g_z != r {
            return Err(BroadcastMsgError::InvalidCypherText.into());
        }

        Ok(())
    }

    fn compute_share_committment(&self, k: u32) -> V::Public {
        let mut out = V::Public::zero();

        for l in 0..self.poly.degree() + 1 {
            let mut coeff = self.poly.get(l);
            let sc = Scalar::from(k.pow(l));
            coeff.mul(&sc);
            out.add(&coeff);
        }

        out
    }
}
