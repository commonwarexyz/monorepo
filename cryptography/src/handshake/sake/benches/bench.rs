use commonware_cryptography::{
    ChaCha20Poly1305, Signer,
    ed25519::PrivateKey,
    handshake::sake::{Context, Error, Version, dial_end, dial_start, listen_end, listen_start},
};
use commonware_math::algebra::Random;
use criterion::criterion_main;
use rand::SeedableRng as _;
use rand_chacha::ChaCha8Rng;

mod sake;
mod transport;

fn connect() -> Result<(ChaCha20Poly1305, ChaCha20Poly1305), Error> {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let dialer_crypto = PrivateKey::random(&mut rng);
    let listener_crypto = PrivateKey::random(&mut rng);

    let (d_state, msg1) = dial_start(
        &mut rng,
        Context::new(
            b"bench_namespace",
            0,
            0..1,
            dialer_crypto.clone(),
            listener_crypto.public_key(),
            Version::V1,
        ),
    );
    let (l_state, msg2) = listen_start(
        &mut rng,
        Context::new(
            b"bench_namespace",
            0,
            0..1,
            listener_crypto,
            dialer_crypto.public_key(),
            Version::V1,
        ),
        msg1,
    )?;
    let (msg3, dialer) = dial_end(d_state, msg2)?;
    let listener = listen_end(l_state, msg3)?;
    Ok((
        Random::random(dialer.noise(b"cipher_d2l")),
        Random::random(listener.noise(b"cipher_d2l")),
    ))
}

criterion_main!(sake::benches, transport::benches);
