use commonware_cryptography::{
    bls12381::{
        dkg::Dealer as DKGDealer,
        primitives::{poly, variant::Variant},
    },
    PublicKey,
};
use commonware_utils::set::Set;
use rand::Rng;
use rand_core::CryptoRngCore;

use crate::{broadcast::BroadcastMsg, cyphered_share::CypheredShare, evrf::EVRF};

pub struct Dealer<V: Variant>
where
    <V as Variant>::Public: PublicKey,
{
    inner: DKGDealer<V::Public, V>,
    bmsg: BroadcastMsg<V>,
}

impl<V: Variant> Dealer<V>
where
    <V as Variant>::Public: PublicKey,
{
    pub fn new<R: CryptoRngCore>(rng: &mut R, players: Set<V::Public>, evrf: &EVRF<V>) -> Self {
        let (inner, poly, shares) = DKGDealer::new(rng, None, players.clone());

        let msg: [u8; 32] = rng.gen();

        // Cypher Share
        let shares = shares
            .into_iter()
            .map(|x| {
                let id = x.index;
                let party_pki = players.get(id as usize).expect("Player not found");
                let ervf_out = evrf.evaluate(msg.as_slice(), *party_pki);
                CypheredShare::new(x, ervf_out)
            })
            .collect::<Vec<_>>();

        let bmsg = BroadcastMsg::new(msg.to_vec(), shares, poly);

        Self { inner, bmsg }
    }
}
