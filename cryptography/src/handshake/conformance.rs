//! Handshake conformance tests

use crate::{
    ed25519::PrivateKey,
    handshake::{dial_end, dial_start, listen_end, listen_start, Context},
    transcript::Transcript,
    Signer,
};
use commonware_codec::Encode;
use commonware_conformance::{conformance_tests, Conformance};
use commonware_math::algebra::Random;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

const NAMESPACE: &[u8] = b"_COMMONWARE_HANDSHAKE_CONFORMANCE_TESTS";

struct Handshake;

impl Conformance for Handshake {
    async fn commit(seed: u64) -> Vec<u8> {
        let mut log = Vec::new();
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        let dialer_key = PrivateKey::random(&mut rng);
        let listener_key = PrivateKey::random(&mut rng);

        let (dialer_state, dialer_greeting) = dial_start(
            &mut rng,
            Context::new(
                &Transcript::new(NAMESPACE),
                0,
                0..1,
                dialer_key.clone(),
                listener_key.public_key(),
            ),
        );
        log.extend(dialer_greeting.encode());

        let (listener_state, listener_greeting_ack) = listen_start(
            &mut rng,
            Context::new(
                &Transcript::new(NAMESPACE),
                0,
                0..1,
                listener_key,
                dialer_key.public_key(),
            ),
            dialer_greeting,
        )
        .unwrap();
        log.extend(listener_greeting_ack.encode());

        let (dialer_ack, mut dialer_tx, mut dialer_rx) =
            dial_end(dialer_state, listener_greeting_ack).unwrap();
        log.extend(dialer_ack.encode());

        let (mut listener_tx, mut listener_rx) = listen_end(listener_state, dialer_ack).unwrap();

        // Generate a random message to send to the listener from the dialer.
        let mut random_msg = vec![0u8; rng.gen_range(0..256)];
        rng.fill(&mut random_msg[..]);
        log.extend(random_msg.encode());

        let dialer_ciphertext = dialer_tx.send(random_msg.as_slice()).unwrap();
        assert_ne!(dialer_ciphertext, random_msg);
        log.extend(dialer_ciphertext.encode());

        let received_msg = listener_rx.recv(&dialer_ciphertext).unwrap();
        assert_eq!(received_msg, random_msg);
        log.extend(received_msg.encode());

        // Generate a random message to send to the dialer from the listener.
        let mut random_msg = vec![0u8; rng.gen_range(0..256)];
        rng.fill(&mut random_msg[..]);
        log.extend(random_msg.encode());

        let listener_ciphertext = listener_tx.send(random_msg.as_slice()).unwrap();
        assert_ne!(listener_ciphertext, random_msg);
        log.extend(listener_ciphertext.encode());

        let received_msg = dialer_rx.recv(&listener_ciphertext).unwrap();
        assert_eq!(received_msg, random_msg);
        log.extend(received_msg.encode());

        log
    }
}

conformance_tests! {
    Handshake => 4096,
}
