use commonware_cryptography::{
    Kem, Signer,
    ed25519::PrivateKey,
    handshake::sake::{
        Context, Error, Version, X25519, dial_end, dial_start, listen_end, listen_start,
    },
    ml_kem::MlKem768,
    transcript::Transcript,
};
use commonware_math::algebra::Random;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};

fn connect<K: Kem>(kem: K) -> Result<(Transcript, Transcript), Error> {
    let mut rng = test_rng();
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
            kem.clone(),
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
            kem,
            Version::V1,
        ),
        msg1,
    )?;
    let (msg3, dialer) = dial_end(d_state, msg2)?;
    let listener = listen_end(l_state, msg3)?;
    Ok((dialer, listener))
}

fn bench_connect(c: &mut Criterion) {
    c.bench_function(&format!("{}::connect/kem=x25519", module_path!()), |b| {
        b.iter(|| connect(X25519).unwrap())
    });
    c.bench_function(
        &format!("{}::connect/kem=ml-kem-768", module_path!()),
        |b| b.iter(|| connect(MlKem768).unwrap()),
    );
}

criterion_group!(benches, bench_connect);
