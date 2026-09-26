#![no_main]

use commonware_cryptography::{Signer, ed25519::PrivateKey};
use commonware_runtime::{Runner, Spawner, Supervisor as _, deterministic, mocks};
use commonware_stream::{
    Handshake as _,
    cups::{Handshake, Version},
    utils::Timeout,
};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

static NAMESPACE: &[u8] = b"fuzz_transport";
const MAX_MESSAGE_SIZE: u32 = 64 * 1024; // 64KB buffer

fn fuzz(data: &[u8]) {
    // Pick the protocol version from the first byte.
    let version = if data.first().is_some_and(|byte| byte & 1 == 1) {
        Version::V1
    } else {
        Version::V0
    };
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let dialer_signer = PrivateKey::from_seed(42);
        let listener_signer = PrivateKey::from_seed(24);

        let (dialer_sink, listener_stream) = mocks::Channel::init();
        let (listener_sink, dialer_stream) = mocks::Channel::init();

        let dialer_handshake = Timeout::new(
            Handshake {
                signer: dialer_signer.clone(),
                version,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
            },
            Duration::from_secs(1),
        );

        let listener_handshake = Timeout::new(
            Handshake {
                signer: listener_signer.clone(),
                version,
                synchrony_bound: Duration::from_secs(1),
                max_handshake_age: Duration::from_secs(1),
            },
            Duration::from_secs(1),
        );

        let listener_handle = context.child("listener").spawn(move |context| async move {
            listener_handshake
                .listen(
                    context,
                    NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    |_| async { true },
                    listener_stream,
                    listener_sink,
                )
                .await
        });

        let (mut dialer_sender, mut dialer_receiver) = dialer_handshake
            .dial(
                context.child("dialer"),
                NAMESPACE,
                MAX_MESSAGE_SIZE,
                listener_signer.public_key(),
                dialer_stream,
                dialer_sink,
            )
            .await
            .unwrap();

        let (listener_peer, mut listener_sender, mut listener_receiver) =
            listener_handle.await.unwrap().unwrap();
        assert_eq!(listener_peer, dialer_signer.public_key());

        for chunk in data.chunks(1024) {
            dialer_sender.send(chunk.to_vec()).await.unwrap();
            let recv_result = listener_receiver.recv().await.unwrap();
            assert_eq!(recv_result.coalesce(), chunk);

            listener_sender.send(chunk.to_vec()).await.unwrap();
            let recv_result = dialer_receiver.recv().await.unwrap();
            assert_eq!(recv_result.coalesce(), chunk);
        }
    });
}

fuzz_target!(|input: &[u8]| {
    fuzz(input);
});
