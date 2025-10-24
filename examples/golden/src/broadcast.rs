use std::collections::HashMap;

use crate::cyphered_share::CypheredShare;
use crate::error::Error;
use commonware_cryptography::bls12381::primitives::group::{Element, Scalar};
use commonware_cryptography::bls12381::primitives::{poly, variant::Variant};
use thiserror::Error as ThisError;
#[derive(Debug, ThisError)]
pub enum BroadcastMsgError {
    #[error("Player public key not found {0}")]
    PlayerNotFound(u32),
    #[error("Insufficient amount of shares {0}")]
    UnexpectedShares(u32),
    #[error("Invalid cyphertext")]
    InvalidCypherText,
    #[error("Dealer broadcasted his own share {0}")]
    DealerShareFound(u32),
}

pub struct BroadcastMsg<V: Variant> {
    msg: Vec<u8>,
    shares: Vec<CypheredShare<V>>,
    poly: poly::Public<V>,
}

impl<V: Variant> BroadcastMsg<V> {
    pub fn new(msg: Vec<u8>, shares: Vec<CypheredShare<V>>, poly: poly::Public<V>) -> Self {
        Self { msg, shares, poly }
    }

    /// Validation to be performed every time that a player receives a [`BroadcastMsg`] from a dealer
    /// This function covers steps 7-8-9 of Round1.
    /// If validation is successful, it returns the vector of share commitments
    pub fn validate(
        &self,
        dealer: u32,
        participants: &HashMap<u32, V::Public>,
    ) -> Result<Vec<(u32, V::Public)>, Error> {
        let Some(dealer_pk) = participants.get(&dealer) else {
            return Err(BroadcastMsgError::PlayerNotFound(dealer).into());
        };
        let num_players = participants.len() as u32;
        let shares_len = self.shares.len() as u32;
        if shares_len != num_players - 1 {
            // dealer doesnt broadcast his own share
            return Err(BroadcastMsgError::UnexpectedShares(shares_len).into());
        }

        let mut out = Vec::with_capacity(self.shares.len());

        for cs in &self.shares {
            let k = cs.index();
            if k == dealer {
                return Err(BroadcastMsgError::DealerShareFound(dealer).into());
            }
            let Some(receiver_pk) = participants.get(&k) else {
                return Err(BroadcastMsgError::PlayerNotFound(k).into());
            };
            cs.verify_zk_proof(*dealer_pk, &self.msg, *receiver_pk)?;

            let x_jk = self.verify_validity_of_cyphertext(cs, k)?;
            out.push((k, x_jk));
        }

        // we push also the share commitment of the dealer
        let x_jj = self.compute_share_committment(dealer);
        out.push((dealer, x_jj));

        Ok(out)
    }

    pub fn take_cyphered_share(&mut self, player: u32) -> Option<CypheredShare<V>> {
        let position = self.shares.iter().position(|x| x.index() == player)?;
        let out = self.shares.remove(position);
        Some(out)
    }

    pub fn msg(&self) -> &[u8] {
        &self.msg
    }

    pub fn commitment_omega(&self) -> V::Public {
        self.poly.get(0)
    }

    /// Step (9)
    fn verify_validity_of_cyphertext(
        &self,
        cs: &CypheredShare<V>,
        k: u32,
    ) -> Result<V::Public, Error> {
        let g_z = cs.commitment_cyphered_share();
        let mut r = cs.commitment_random_scalar();
        let x = self.compute_share_committment(k);
        r.add(&x);

        if g_z != r {
            return Err(BroadcastMsgError::InvalidCypherText.into());
        }

        Ok(x)
    }

    /// X_{j,k}
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
