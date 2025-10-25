mod broadcast;
mod cyphered_share;
mod error;

mod participant;

#[cfg(test)]
mod test {
    use crate::error::Error;
    use crate::participant::{evrf::EVRF, registry::Registry, Participant};
    use commonware_cryptography::bls12381::primitives::group::{Element, Scalar};
    use commonware_utils::set::Ordered;
    use rand::thread_rng;

    #[test]
    fn test_generation() -> Result<(), Error> {
        let beta = Scalar::one();
        let rng = &mut thread_rng();

        let num_players = 3;

        // Generate participants
        let evrfs: Vec<_> = (0..num_players)
            .map(|_| EVRF::random(rng, beta.clone()))
            .collect();

        let mut participants = Vec::with_capacity(num_players);
        let mut players = Vec::with_capacity(num_players);

        for evrf in evrfs {
            let registry = Registry::default();
            let part = Participant::new(evrf, registry);
            players.push(part.pk_i().clone());
            participants.push(part);
        }

        participants.sort_by_key(|x| x.pk_i().clone());

        let players = Ordered::from(players);

        // Dealing
        let mut bmsgs = Vec::with_capacity(participants.len());
        for dealer in &participants {
            let bmsg = dealer.generate_bmsg(rng, players.clone());
            bmsgs.push(bmsg);
        }

        //Evaluation
        for (j, bmsg) in bmsgs.into_iter().enumerate() {
            for (k, player) in participants.iter_mut().enumerate() {
                player.on_incoming_bmsg(j as u32, k as u32, bmsg.clone(), &players)?;
            }
        }

        // Assessment: the group pubkey should be equal for all, and also the registrybof all pubkeys
        let expected_group = participants[0]
            .get_group_pubkey()
            .expect("Group should be ready");

        let eq_group = participants.iter().all(|x| {
            let group_p = x.get_group_pubkey().expect("Group should be ready");
            group_p == expected_group
        });

        assert!(eq_group, "Group pubkey mismatch");

        let expected_pubkeys = participants[0].players_pubkeys();

        let eq_pubkeys = participants.iter().all(|x| {
            let pubkeys = x.players_pubkeys();
            pubkeys == expected_pubkeys
        });

        assert!(eq_pubkeys, "Players pubkeys mismatch");

        Ok(())
    }
}
