mod broadcast;
mod cyphered_share;
mod error;
mod evrf;
mod registry;

#[cfg(test)]
mod test {
    use super::*;
    use crate::broadcast::BroadcastMsg;
    use crate::cyphered_share::CypheredShare;
    use crate::evrf::EVRF;
    use crate::registry::Registry;
    use commonware_cryptography::bls12381::dkg::Dealer as DKGDealer;
    use commonware_cryptography::bls12381::primitives::group::{Element, Scalar};
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use commonware_cryptography::bls12381::PublicKey;
    use commonware_utils::set::Set;
    use rand::thread_rng;
    use rand::Rng;
    use rand_core::CryptoRngCore;

    #[derive(Clone)]
    struct Participant {
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
            players: Set<PublicKey>,
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
    }

    #[test]
    fn test_generation() {
        let beta = Scalar::one();
        let rng = &mut thread_rng();

        let num_players = 3;

        let evrfs: Vec<_> = (0..num_players)
            .map(|_| EVRF::random(rng, beta.clone()))
            .collect();

        let mut participants = Vec::with_capacity(num_players);

        for (i, evrf) in evrfs.into_iter().enumerate() {
            let registry = Registry::new(i as u32);
            let part = Participant::new(evrf, registry);
            participants.push(part);
        }

        let players = Set::new_by_key(participants.clone(), |x| x.evrf.pk_i().clone());
    }
}
