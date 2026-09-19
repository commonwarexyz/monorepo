#![no_main]

use commonware_cryptography::{Signer, ed25519::PrivateKey};
use commonware_runtime::{Runner, Spawner, Supervisor as _, deterministic, mocks};
use commonware_stream::{
    Handshake as _,
    cups::{Handshake, Receiver, Sender, Version},
    utils::Timeout,
};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use std::{cell::RefCell, time::Duration};

static NAMESPACE: &[u8] = b"lazy_fuzz_transport";
const MAX_MESSAGE_SIZE: u32 = 1023 * 1024; // ~1MB buffer

struct TransportPair {
    dialer_sender: Sender<mocks::Sink>,
    listener_receiver: Receiver<mocks::Stream>,
}

thread_local! {
    static TRANSPORT: RefCell<Option<TransportPair>> = RefCell::new({
        let executor = deterministic::Runner::default();

        let transport_pair = executor.start(|context| async move {
            let dialer_signer = PrivateKey::from_seed(42);
            let listener_signer = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            let dialer_handshake = Timeout::new(
                Handshake {
                    signer: dialer_signer.clone(),
                    version: Version::V1,
                    synchrony_bound: Duration::from_secs(3),
                    max_handshake_age: Duration::from_secs(5),
                },
                Duration::from_secs(2),
            );

            let listener_handshake = Timeout::new(
                Handshake {
                    signer: listener_signer.clone(),
                    version: Version::V1,
                    synchrony_bound: Duration::from_secs(3),
                    max_handshake_age: Duration::from_secs(5),
                },
                Duration::from_secs(2),
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

            let (dialer_sender, _) = dialer_handshake
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

            let (listener_peer, _, listener_receiver) =
                listener_handle.await.unwrap().unwrap();
            assert_eq!(listener_peer, dialer_signer.public_key());

            TransportPair {
                dialer_sender,
                listener_receiver,
            }
        });

        Some(transport_pair)
    });
}

fn fuzz(data: &[u8]) {
    if data.is_empty() || data.len() > MAX_MESSAGE_SIZE as usize {
        return;
    }

    TRANSPORT.with(|transport_cell| {
        let mut transport_opt = transport_cell.borrow_mut();
        let transport = match transport_opt.as_mut() {
            Some(t) => t,
            None => return,
        };

        for chunk in data.chunks(1024) {
            block_on(transport.dialer_sender.send(chunk.to_vec())).unwrap();

            let received = block_on(transport.listener_receiver.recv()).unwrap();
            assert_eq!(received.coalesce(), chunk, "Data corruption detected");
        }
    });
}

fuzz_target!(|input: &[u8]| {
    fuzz(input);
});
