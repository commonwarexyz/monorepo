#![no_main]

use commonware_cryptography::{ed25519::PrivateKey, Signer};
use commonware_runtime::{deterministic, mocks, Runner, Spawner};
use commonware_stream::{dial, listen, Config, Receiver, Sender};
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
            let dialer_crypto = PrivateKey::from_seed(42);
            let listener_crypto = PrivateKey::from_seed(24);

            let (dialer_sink, listener_stream) = mocks::Channel::init();
            let (listener_sink, dialer_stream) = mocks::Channel::init();

            let dialer_config = Config {
                signing_key: dialer_crypto.clone(),
                namespace: NAMESPACE.to_vec(),
                max_message_size: MAX_MESSAGE_SIZE,
                synchrony_bound: Duration::from_secs(3),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(2),
            };

            let listener_config = Config {
                signing_key: listener_crypto.clone(),
                namespace: NAMESPACE.to_vec(),
                max_message_size: MAX_MESSAGE_SIZE,
                synchrony_bound: Duration::from_secs(3),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(2),
            };


        let listener_handle = context.clone().spawn(move |context| async move {
            listen(
                context,
                |_| async { true },
                listener_config,
                listener_stream,
                listener_sink,
            ).await
        });

        let (dialer_sender, _) = dial(
            context.clone(),
            dialer_config,
            listener_crypto.public_key(),
            dialer_stream,
            dialer_sink,
        )
        .await
        .unwrap();

        let (listener_peer, _, listener_receiver) =
            listener_handle.await.unwrap().unwrap();
        assert_eq!(listener_peer, dialer_crypto.public_key());

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
            block_on(transport.dialer_sender.send(chunk)).unwrap();

            let received = block_on(transport.listener_receiver.recv()).unwrap();
            assert_eq!(&received[..], chunk, "Data corruption detected");
        }
    });
}

fuzz_target!(|input: &[u8]| {
    fuzz(input);
});
