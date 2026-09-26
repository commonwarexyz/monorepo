//! SAKE conformance tests

use crate::{
    Signer,
    ed25519::PrivateKey,
    handshake::sake::{Context, Version, dial_end, dial_start, listen_end, listen_start},
};
use commonware_codec::Encode;
use commonware_conformance::{Conformance, conformance_tests};
use commonware_math::algebra::Random;
use rand::{RngExt as _, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Runs a full handshake and message exchange for `version`, logging every encoded artifact.
fn exchange(seed: u64, version: Version) -> Vec<u8> {
    let mut log = Vec::new();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    // Namespaces of 128 bytes or more reach the multi-byte packet lengths where transcript
    // framings differ, and a nonzero high byte pins the timestamp byte order. The listener's clock
    // runs ahead of the dialer's, so each message carries its sender's own timestamp.
    let mut namespace = vec![0u8; rng.random_range(0..=300)];
    rng.fill(&mut namespace[..]);
    let dialer_time = rng.random_range(1u64 << 56..1 << 63);
    let listener_time = dialer_time + rng.random_range(1..1000);

    let dialer_key = PrivateKey::random(&mut rng);
    let listener_key = PrivateKey::random(&mut rng);

    let (dialer_state, dialer_greeting) = dial_start(
        &mut rng,
        Context::new(
            &namespace,
            version,
            dialer_time,
            listener_time..listener_time + 1,
            dialer_key.clone(),
            listener_key.public_key(),
        ),
    );
    log.extend(dialer_greeting.encode());

    let (listener_state, listener_greeting_ack) = listen_start(
        &mut rng,
        Context::new(
            &namespace,
            version,
            listener_time,
            dialer_time..dialer_time + 1,
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

    // Exchange several messages in each direction so successive nonces are covered.
    for _ in 0..3 {
        // Send a random message from the dialer to the listener.
        let mut random_msg = vec![0u8; rng.random_range(0..256)];
        rng.fill(&mut random_msg[..]);
        log.extend(random_msg.encode());

        let dialer_ciphertext = dialer_tx.send(random_msg.as_slice()).unwrap();
        assert_ne!(dialer_ciphertext, random_msg);
        log.extend(dialer_ciphertext.encode());

        let received_msg = listener_rx.recv(&dialer_ciphertext).unwrap();
        assert_eq!(received_msg, random_msg);
        log.extend(received_msg.encode());

        // Send a random message from the listener to the dialer.
        let mut random_msg = vec![0u8; rng.random_range(0..256)];
        rng.fill(&mut random_msg[..]);
        log.extend(random_msg.encode());

        let listener_ciphertext = listener_tx.send(random_msg.as_slice()).unwrap();
        assert_ne!(listener_ciphertext, random_msg);
        log.extend(listener_ciphertext.encode());

        let received_msg = dialer_rx.recv(&listener_ciphertext).unwrap();
        assert_eq!(received_msg, random_msg);
        log.extend(received_msg.encode());
    }

    log
}

struct SakeV0;

impl Conformance for SakeV0 {
    async fn commit(seed: u64) -> Vec<u8> {
        exchange(seed, Version::V0)
    }
}

struct SakeV1;

impl Conformance for SakeV1 {
    async fn commit(seed: u64) -> Vec<u8> {
        exchange(seed, Version::V1)
    }
}

conformance_tests! {
    SakeV0 => 4096,
    SakeV1 => 4096,
}
