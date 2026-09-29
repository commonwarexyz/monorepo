#![no_main]

use commonware_cryptography::{ChaCha20Poly1305, Signer, ed25519::PrivateKey};
use commonware_runtime::{Runner, Spawner, Supervisor as _, deterministic, mocks};
use commonware_stream::{
    SakeCups, Upgrader as StreamUpgrader,
    cups::{self, Cups},
    sake::{Sake, Version},
    utils::Timeout,
};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use std::{cell::RefCell, time::Duration};

/// Returns the records that pair with the SAKE `version`.
fn records(version: Version) -> Cups<ChaCha20Poly1305> {
    Cups::new(match version {
        Version::V0 => cups::Version::V0,
        Version::V1 => cups::Version::V1,
    })
}

static NAMESPACE: &[u8] = b"lazy_fuzz_transport";
const MAX_MESSAGE_SIZE: u32 = 1023 * 1024; // ~1MB buffer

/// Sending half of an [Upgrader] connection over mock channels.
type Sender = <SakeCups<PrivateKey> as StreamUpgrader>::Sender<mocks::Stream, mocks::Sink>;

/// Receiving half of an [Upgrader] connection over mock channels.
type Receiver = <SakeCups<PrivateKey> as StreamUpgrader>::Receiver<mocks::Stream, mocks::Sink>;

struct TransportPair {
    dialer_sender: Sender,
    listener_receiver: Receiver,
}

/// Establishes a connected transport pair for `version`.
fn connect(version: Version) -> TransportPair {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let dialer_signer = PrivateKey::from_seed(42);
        let listener_signer = PrivateKey::from_seed(24);

        let (dialer_sink, listener_stream) = mocks::Channel::init();
        let (listener_sink, dialer_stream) = mocks::Channel::init();

        let dialer_handshake = (
            Sake {
                signer: dialer_signer.clone(),
                synchrony_bound: Duration::from_secs(3),
                max_handshake_age: Duration::from_secs(5),
                version,
            },
            records(version),
        );
        let dialer_handshake = Timeout::new(dialer_handshake, Duration::from_secs(2));

        let listener_handshake = (
            Sake {
                signer: listener_signer.clone(),
                synchrony_bound: Duration::from_secs(3),
                max_handshake_age: Duration::from_secs(5),
                version,
            },
            records(version),
        );
        let listener_handshake = Timeout::new(listener_handshake, Duration::from_secs(2));

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

        let (listener_peer, _, listener_receiver) = listener_handle.await.unwrap().unwrap();
        assert_eq!(listener_peer, dialer_signer.public_key());

        TransportPair {
            dialer_sender,
            listener_receiver,
        }
    })
}

thread_local! {
    static TRANSPORTS: RefCell<[TransportPair; 2]> =
        RefCell::new([connect(Version::V0), connect(Version::V1)]);
}

fn fuzz(data: &[u8]) {
    if data.is_empty() || data.len() > MAX_MESSAGE_SIZE as usize {
        return;
    }

    TRANSPORTS.with(|transports| {
        // Pick the protocol version from the first byte.
        let transport = &mut transports.borrow_mut()[usize::from(data[0] & 1)];

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
