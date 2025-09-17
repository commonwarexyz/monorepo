use commonware_cryptography::{
    ed25519::PrivateKey,
    handshake::{
        dial_end, dial_start, listen_end, listen_start, Context, Error, RecvCipher, SendCipher,
    },
    PrivateKeyExt as _, Signer,
};
use criterion::criterion_main;
use rand::SeedableRng as _;
use rand_chacha::ChaCha8Rng;

mod handshake;
mod transport;

fn connect() -> Result<(SendCipher, RecvCipher), Error> {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let dialer_crypto = PrivateKey::from_rng(&mut rng);
    let listener_crypto = PrivateKey::from_rng(&mut rng);

    let (d_state, msg1) = dial_start(
        &mut rng,
        Context::new(0, 0..1, dialer_crypto.clone(), listener_crypto.public_key()),
    );
    let (l_state, msg2) = listen_start(
        &mut rng,
        Context::new(0, 0..1, listener_crypto, dialer_crypto.public_key()),
        msg1,
    )?;
    let (msg3, d_send, _) = dial_end(d_state, msg2)?;
    let (_, l_recv) = listen_end(l_state, msg3)?;
    Ok((d_send, l_recv))
}

criterion_main!(handshake::benches, transport::benches);
