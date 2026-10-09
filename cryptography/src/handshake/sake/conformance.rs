//! SAKE conformance tests

use crate::{
    Kem, Signer,
    ed25519::PrivateKey,
    handshake::sake::{
        Ack, Context, Version, X25519, dial_end, dial_start, listen_end, listen_start,
    },
};
use commonware_codec::{Encode, conformance::CodecConformance};
use commonware_conformance::{Conformance, conformance_tests};
use commonware_math::algebra::Random;
use commonware_utils::TestRng;
use rand::RngExt as _;

type Syn<S, K = X25519> = super::Syn<S, K>;
type SynAck<S, K = X25519> = super::SynAck<S, K>;

/// Runs a full handshake for `version`, logging every message and the summary of the resulting
/// transcript.
fn exchange<K: Kem>(seed: u64, kem: K, version: Version) -> Vec<u8> {
    let mut rng = TestRng::new(seed);
    let mut log = Vec::new();

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
            dialer_time,
            listener_time..listener_time + 1,
            dialer_key.clone(),
            listener_key.public_key(),
            kem.clone(),
            version,
        ),
    );
    log.extend(dialer_greeting.encode());

    let (listener_state, listener_greeting_ack) = listen_start(
        &mut rng,
        Context::new(
            &namespace,
            listener_time,
            dialer_time..dialer_time + 1,
            listener_key,
            dialer_key.public_key(),
            kem,
            version,
        ),
        dialer_greeting,
    )
    .unwrap();
    log.extend(listener_greeting_ack.encode());

    let (dialer_ack, dialer_transcript) = dial_end(dialer_state, listener_greeting_ack).unwrap();
    log.extend(dialer_ack.encode());

    let listener_transcript = listen_end(listener_state, dialer_ack).unwrap();
    let summary = dialer_transcript.summarize();
    assert_eq!(summary, listener_transcript.summarize());
    log.extend(summary.encode());

    log
}

struct SakeV0;

impl Conformance for SakeV0 {
    async fn commit(seed: u64) -> Vec<u8> {
        exchange(seed, X25519, Version::V0)
    }
}

struct SakeV1;

impl Conformance for SakeV1 {
    async fn commit(seed: u64) -> Vec<u8> {
        exchange(seed, X25519, Version::V1)
    }
}

conformance_tests! {
    SakeV0 => 4096,
    SakeV1 => 4096,
    CodecConformance<Syn<crate::ed25519::Signature>>,
    CodecConformance<SynAck<crate::ed25519::Signature>>,
    CodecConformance<Ack>,
}

#[cfg(not(any(
    commonware_stability_BETA,
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
mod ml_kem {
    use super::*;
    use crate::ml_kem::MlKem768;

    struct SakeMlKem768V0;

    impl Conformance for SakeMlKem768V0 {
        async fn commit(seed: u64) -> Vec<u8> {
            exchange(seed, MlKem768, Version::V0)
        }
    }

    struct SakeMlKem768V1;

    impl Conformance for SakeMlKem768V1 {
        async fn commit(seed: u64) -> Vec<u8> {
            exchange(seed, MlKem768, Version::V1)
        }
    }

    conformance_tests! {
        SakeMlKem768V0 => 1024,
        SakeMlKem768V1 => 1024,
        CodecConformance<Syn<crate::ed25519::Signature, MlKem768>>,
        CodecConformance<SynAck<crate::ed25519::Signature, MlKem768>>,
    }
}
