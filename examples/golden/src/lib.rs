pub mod broadcast;
pub mod ciphered_share;
pub mod error;
pub mod participant;

#[cfg(test)]
mod test {
    use crate::error::Error;
    use crate::participant::{evrf::EVRF, registry::Registry, Participant};
    use commonware_cryptography::bls12381::primitives::group::{Element, Scalar};
    use commonware_cryptography::bls12381::primitives::ops::{
        sign_message, threshold_signature_recover,
    };
    use commonware_cryptography::bls12381::primitives::poly::Eval;
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use commonware_cryptography::bls12381::tle::Block;
    use commonware_cryptography::bls12381::tle::{decrypt, encrypt};
    use commonware_cryptography::bls12381::PublicKey;
    use commonware_utils::quorum;
    use commonware_utils::set::Ordered;
    use rand::thread_rng;
    use rand_core::CryptoRngCore;

    #[test]
    fn test_golden_dkg() -> Result<(), Error> {
        let beta = Scalar::one();
        let rng = &mut thread_rng();

        let num_players = 3;
        let participants = golden_dkg(rng, beta, num_players)?;

        // Assessment: the group pubkey should be equal for all, and also the registrybof all pubkeys
        verify_correctness_of_group_key(&participants);

        Ok(())
    }

    #[test]
    fn test_golden_tle() -> Result<(), Error> {
        let beta = Scalar::one();
        let rng = &mut thread_rng();

        let num_players = 3;
        let t = quorum(num_players);

        let participants = golden_dkg(rng, beta, num_players as usize)?;

        let group_public_key = participants[0].get_group_pubkey().expect("group public");

        // Step 3: Define your encryption target (e.g., a future timestamp or round number)
        let target = 12345u64.to_be_bytes();
        let namespace = Some(&b"my_app"[..]); // Optional namespace for domain separation

        // Step 4: Create your 32-byte message to encrypt
        let message_bytes = b"This is my secret message!!!!!!!"; // Must be exactly 32 bytes
        let message = Block::new(*message_bytes);

        // Step 5: Encrypt the message for the target using the group public key
        let ciphertext = encrypt::<_, MinPk>(
            rng,
            *group_public_key.as_ref(),
            (namespace, &target),
            &message,
        );

        // Step 6: Later, when you want to decrypt...
        // Each participant generates a partial signature over the target
        let partial_signatures: Vec<_> = participants
            .iter()
            .take(t as usize) // Only need threshold number of partials
            .enumerate()
            .map(|(k, p)| {
                let sig = sign_message::<MinPk>(p.get_share().expect("share"), namespace, &target);
                Eval {
                    value: sig,
                    index: k as u32,
                }
            })
            .collect();

        // Step 7: Recover the threshold signature from partial signatures
        let threshold_signature = threshold_signature_recover::<MinPk, _>(t, &partial_signatures)
            .expect("Should recover threshold signature");

        // Step 8: Decrypt the message using the threshold signature
        let decrypted =
            decrypt::<MinPk>(&threshold_signature, &ciphertext).expect("Decryption should succeed");

        assert_eq!(message.as_ref(), decrypted.as_ref());

        Ok(())
    }

    fn golden_dkg<R: CryptoRngCore>(
        rng: &mut R,
        beta: Scalar,
        num_players: usize,
    ) -> Result<Vec<Participant>, Error> {
        // Generate participants
        let (mut participants, players) = create_participants(rng, beta, num_players);

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

        Ok(participants)
    }

    fn create_participants<R: CryptoRngCore>(
        rng: &mut R,
        beta: Scalar,
        num_players: usize,
    ) -> (Vec<Participant>, Ordered<PublicKey>) {
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
        (participants, players)
    }

    fn verify_correctness_of_group_key(participants: &[Participant]) {
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
    }
}
