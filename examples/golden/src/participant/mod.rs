use commonware_cryptography::bls12381::dkg::Dealer as DKGDealer;
use commonware_cryptography::bls12381::primitives::group::G1;
use commonware_cryptography::bls12381::primitives::variant::MinPk;
use commonware_cryptography::bls12381::PublicKey;
use commonware_utils::set::Ordered;
use rand::Rng;
use rand_core::CryptoRngCore;
use std::collections::HashMap;

use crate::broadcast::BroadcastMsg;
use crate::cyphered_share::CypheredShare;
use crate::error::Error;

pub mod evrf;
pub mod registry;
use evrf::EVRF;
use registry::Registry;

#[derive(Clone)]
pub struct Participant {
    registry: Registry,
    evrf: EVRF,
}

impl Participant {
    pub fn new(evrf: EVRF, registry: Registry) -> Self {
        Self { evrf, registry }
    }

    pub fn generate_bmsg<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        players: Ordered<PublicKey>,
    ) -> BroadcastMsg {
        let (_, poly, shares) = DKGDealer::<PublicKey, MinPk>::new(rng, None, players.clone());

        let msg: [u8; 32] = rng.gen();

        // Cypher Share
        let shares = shares
            .into_iter()
            .map(|x| {
                let id = x.index;
                let party_pki = players.get(id as usize).expect("Player not found");
                let ervf_out = self.evrf.evaluate(msg.as_slice(), party_pki);

                CypheredShare::new(x, ervf_out)
            })
            .collect::<Vec<_>>();

        BroadcastMsg::new(msg.to_vec(), shares, poly)
    }

    pub fn pk_i(&self) -> &PublicKey {
        self.evrf.pk_i()
    }

    pub fn on_incoming_bmsg(
        &mut self,
        dealer: u32,
        player_id: u32,
        bmsg: BroadcastMsg,
        players: &Ordered<PublicKey>,
    ) -> Result<(), Error> {
        self.registry
            .on_incoming_bmsg(dealer, player_id, bmsg, players, &self.evrf)
    }

    pub fn get_group_pubkey(&self) -> Option<PublicKey> {
        self.registry.get_group_pubkey()
    }

    pub fn players_pubkeys(&self) -> &HashMap<u32, G1> {
        self.registry.players_pubkeys()
    }
}
