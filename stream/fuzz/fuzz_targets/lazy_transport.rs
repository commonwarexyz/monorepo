#![no_main]

use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt as _, Signer};
use commonware_runtime::{deterministic, mocks, Runner, Spawner};
use commonware_stream::{
    public_key::{Config, Connection, IncomingConnection, Receiver, Sender},
    Receiver as _, Sender as _,
};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use std::{cell::RefCell, time::Duration};

static NAMESPACE: &[u8] = b"lazy_fuzz_transport";
const MAX_MESSAGE_SIZE: usize = 1023 * 1024; // 64KB buffer

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
                crypto: dialer_crypto.clone(),
                namespace: NAMESPACE.to_vec(),
                max_message_size: MAX_MESSAGE_SIZE,
                synchrony_bound: Duration::from_secs(3),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(2),
            };

            let listener_config = Config {
                crypto: listener_crypto.clone(),
                namespace: NAMESPACE.to_vec(),
                max_message_size: MAX_MESSAGE_SIZE,
                synchrony_bound: Duration::from_secs(3),
                max_handshake_age: Duration::from_secs(5),
                handshake_timeout: Duration::from_secs(2),
            };

            let listener_handle = context.clone().spawn(move |context| async move {
                let incoming = IncomingConnection::verify(
                    &context,
                    listener_config,
                    listener_sink,
                    listener_stream,
                ).await?;
                Connection::upgrade_listener(context, incoming).await
            });

            let dialer_connection = Connection::upgrade_dialer(
                context.clone(),
                dialer_config,
                dialer_sink,
                dialer_stream,
                listener_crypto.public_key(),
            ).await.expect("Dialer connection should succeed");

            let listener_connection = listener_handle.await
                .expect("Listener handle should succeed")
                .expect("Listener connection should succeed");

            let (dialer_sender, _) = dialer_connection.split();
            let (_, listener_receiver) = listener_connection.split();

            TransportPair {
                dialer_sender,
                listener_receiver,
            }
        });

        Some(transport_pair)
    });
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_MESSAGE_SIZE {
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

            let received = block_on(transport.listener_receiver.receive()).unwrap();
            assert_eq!(&received[..], chunk, "Data corruption detected");
        }
    });
});
