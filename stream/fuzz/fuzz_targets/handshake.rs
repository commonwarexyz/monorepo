#![no_main]

use commonware_codec::Encode;
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    PrivateKeyExt as _, Signer,
};
use commonware_runtime::{deterministic, mocks, Metrics, Runner, Spawner};
use commonware_stream::{
    public_key::{
        handshake::{Info, Signed},
        x25519, Config, IncomingConnection,
    },
    utils::codec::send_frame,
};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

#[derive(Debug)]
pub struct FuzzInput {
    dialer_seed: u64,
    listener_seed: u64,
    random_peer: PublicKey,
    ephemeral_public_key: x25519::PublicKey,
    namespace: Vec<u8>,
    max_message_size: usize,
    timestamp: u64,
    synchrony_bound_secs: u64,
    max_handshake_age_secs: u64,
    handshake_timeout_secs: u64,
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let dialer_seed = u64::arbitrary(u)?;
        let dialer_crypto = PrivateKey::from_seed(dialer_seed);
        let listener_seed = dialer_seed.wrapping_add(1);
        let ephemeral_public_key = x25519::PublicKey::from_bytes(u.arbitrary::<[u8; 32]>()?);

        let use_valid_pub_key = u.int_in_range(0..=1)? == 1;
        let random_peer = if use_valid_pub_key {
            dialer_crypto.public_key()
        } else {
            let seed = u64::arbitrary(u)?;
            PrivateKey::from_seed(seed).public_key()
        };

        let namespace_len = u.int_in_range(0..=256)?;
        let namespace = (0..namespace_len)
            .map(|_| u8::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        let max_message_size = u.int_in_range(0..=1024 * 1023)?;
        let timestamp = u.int_in_range(0..=1000)?;
        let synchrony_bound_secs = u.int_in_range(0..=1000)?;
        let max_handshake_age_secs = u.int_in_range(0..=1000)?;
        let handshake_timeout_secs = u.int_in_range(0..=1000)?;

        Ok(FuzzInput {
            dialer_seed,
            listener_seed,
            namespace,
            max_message_size,
            timestamp,
            synchrony_bound_secs,
            max_handshake_age_secs,
            handshake_timeout_secs,
            ephemeral_public_key,
            random_peer,
        })
    }
}

fuzz_target!(|input: FuzzInput| {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let mut dialer_crypto = PrivateKey::from_seed(input.dialer_seed);
        let listener_crypto = PrivateKey::from_seed(input.listener_seed);
        let synchrony_bound = Duration::from_secs(input.synchrony_bound_secs);
        let max_handshake_age = Duration::from_secs(input.max_handshake_age_secs);
        let handshake_timeout = Duration::from_secs(input.handshake_timeout_secs);

        let handshake = Signed::sign(
            &mut dialer_crypto,
            input.namespace.as_slice(),
            Info::new(
                input.random_peer,
                input.ephemeral_public_key,
                input.timestamp,
            ),
        );

        let (sink, _) = mocks::Channel::init();
        let (mut stream_sender, stream) = mocks::Channel::init();

        context
            .with_label("stream_sender")
            .spawn(move |_| async move {
                // Our target is panic.
                let _ = send_frame(
                    &mut stream_sender,
                    &handshake.encode(),
                    input.max_message_size,
                )
                .await;
            });

        let config = Config {
            crypto: listener_crypto,
            namespace: Vec::from(input.namespace.as_slice()),
            max_message_size: input.max_message_size,
            synchrony_bound,
            max_handshake_age,
            handshake_timeout,
        };

        // Our target is panic.
        let _ = IncomingConnection::verify(&context, config, sink, stream).await;
    });
});
