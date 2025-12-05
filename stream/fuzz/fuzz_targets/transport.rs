#![no_main]

use commonware_cryptography::{ed25519::PrivateKey, Signer};
use commonware_runtime::{deterministic, mocks, Runner, Spawner};
use commonware_stream::{dial, listen, Config};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

static NAMESPACE: &[u8] = b"fuzz_transport";
const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64KB buffer

fn fuzz(data: &[u8]) {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let dialer_crypto = PrivateKey::from_seed(42);
        let listener_crypto = PrivateKey::from_seed(24);

        let (dialer_sink, listener_stream) = mocks::Channel::init();
        let (listener_sink, dialer_stream) = mocks::Channel::init();

        let dialer_config = Config {
            signing_key: dialer_crypto.clone(),
            namespace: NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(1),
        };

        let listener_config = Config {
            signing_key: listener_crypto.clone(),
            namespace: NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(1),
        };

        let listener_handle = context.clone().spawn(move |context| async move {
            listen(
                context,
                |_| async { true },
                listener_config,
                listener_stream,
                listener_sink,
            )
            .await
        });

        let (mut dialer_sender, mut dialer_receiver) = dial(
            context.clone(),
            dialer_config,
            listener_crypto.public_key(),
            dialer_stream,
            dialer_sink,
        )
        .await
        .unwrap();

        let (listener_peer, mut listener_sender, mut listener_receiver) =
            listener_handle.await.unwrap().unwrap();
        assert_eq!(listener_peer, dialer_crypto.public_key());

        for chunk in data.chunks(1024) {
            dialer_sender.send(chunk).await.unwrap();
            let recv_result = listener_receiver.recv().await.unwrap();
            assert_eq!(recv_result, chunk);

            listener_sender.send(chunk).await.unwrap();
            let recv_result = dialer_receiver.recv().await.unwrap();
            assert_eq!(recv_result, chunk);
        }
    });
}

fuzz_target!(|input: &[u8]| {
    fuzz(input);
});
