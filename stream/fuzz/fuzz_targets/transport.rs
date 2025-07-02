#![no_main]

use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt as _, Signer};
use commonware_runtime::{deterministic, mocks, Runner, Spawner};
use commonware_stream::{
    public_key::{Config, Connection, IncomingConnection},
    Receiver as _, Sender as _,
};
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
            crypto: dialer_crypto.clone(),
            namespace: NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(1),
        };

        let listener_config = Config {
            crypto: listener_crypto.clone(),
            namespace: NAMESPACE.to_vec(),
            max_message_size: MAX_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(1),
        };

        let listener_handle = context.clone().spawn(move |context| async move {
            let incoming = IncomingConnection::verify(
                &context,
                listener_config,
                listener_sink,
                listener_stream,
            )
            .await?;
            Connection::upgrade_listener(context, incoming).await
        });

        let dialer_connection = Connection::upgrade_dialer(
            context.clone(),
            dialer_config,
            dialer_sink,
            dialer_stream,
            listener_crypto.public_key(),
        )
        .await
        .unwrap();

        let listener_connection = listener_handle.await.unwrap().unwrap();

        let (mut dialer_sender, mut dialer_receiver) = dialer_connection.split();
        let (mut listener_sender, mut listener_receiver) = listener_connection.split();

        for chunk in data.chunks(1024) {
            dialer_sender.send(chunk).await.unwrap();
            let recv_result = listener_receiver.receive().await.unwrap();
            assert_eq!(recv_result, chunk);

            listener_sender.send(chunk).await.unwrap();
            let recv_result = dialer_receiver.receive().await.unwrap();
            assert_eq!(recv_result, chunk);
        }
    });
}

fuzz_target!(|input: &[u8]| {
    fuzz(input);
});
