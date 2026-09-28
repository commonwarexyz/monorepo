//! SAKE conformance tests

use crate::{
    ChaCha20Poly1305, Cipher, Signer,
    ed25519::PrivateKey,
    handshake::sake::{Context, Version, dial_end, dial_start, listen_end, listen_start},
};
use commonware_codec::Encode;
use commonware_conformance::{Conformance, conformance_tests};
use commonware_math::algebra::Random;
use rand::{RngExt as _, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Seals `msg` with `send`, opens it with `recv`, and logs the ciphertext and the plaintext.
fn relay(
    log: &mut Vec<u8>,
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    msg: &[u8],
) -> (ChaCha20Poly1305, ChaCha20Poly1305) {
    // Seal the message in place and log the ciphertext followed by its tag.
    let mut data = msg.to_vec();
    let (send, tag) = send.seal(&[], &mut data).unwrap();
    let mut sealed = data.clone();
    sealed.extend_from_slice(&tag);
    assert_ne!(sealed, msg);
    log.extend(sealed.encode());

    // Open the ciphertext in place and log the recovered plaintext.
    let recv = recv.open(&[], &mut data, &tag).unwrap();
    assert_eq!(data, msg);
    log.extend(data.encode());
    (send, recv)
}

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
        dial_end::<ChaCha20Poly1305, _>(dialer_state, listener_greeting_ack).unwrap();
    log.extend(dialer_ack.encode());

    let (mut listener_tx, mut listener_rx) =
        listen_end::<ChaCha20Poly1305>(listener_state, dialer_ack).unwrap();

    // Exchange several messages in each direction so successive nonces are covered.
    for _ in 0..3 {
        // Send a random message from the dialer to the listener.
        let mut random_msg = vec![0u8; rng.random_range(0..256)];
        rng.fill(&mut random_msg[..]);
        log.extend(random_msg.encode());

        (dialer_tx, listener_rx) = relay(&mut log, dialer_tx, listener_rx, &random_msg);

        // Send a random message from the listener to the dialer.
        let mut random_msg = vec![0u8; rng.random_range(0..256)];
        rng.fill(&mut random_msg[..]);
        log.extend(random_msg.encode());

        (listener_tx, dialer_rx) = relay(&mut log, listener_tx, dialer_rx, &random_msg);
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
