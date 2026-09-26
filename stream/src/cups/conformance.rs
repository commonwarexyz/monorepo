//! CUPS conformance tests.

use crate::{
    Handshake as _,
    cups::{Handshake, Version},
};
use commonware_conformance::{Conformance, conformance_tests};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_runtime::{
    Clock as _, Error, IoBufs, Runner as _, Sink, Spawner as _, Supervisor as _, deterministic,
    mocks,
};
use commonware_utils::sync::Mutex;
use rand::RngExt as _;
use std::{ops::RangeInclusive, sync::Arc, time::Duration};

const NAMESPACE: &[u8] = b"_COMMONWARE_STREAM_CUPS_CONFORMANCE_TESTS";
const MAX_MESSAGE_SIZE: u32 = 1 << 17;

/// Payload lengths covering one-, two-, and three-byte version 0 length prefixes, and records
/// larger than one item of the default network buffer pool (128 KiB).
const LENGTHS: [RangeInclusive<usize>; 4] = [
    0..=111,
    112..=16_367,
    16_368..=131_053,
    131_054..=MAX_MESSAGE_SIZE as usize,
];

/// Forwards writes to a sink while recording their bytes.
struct Tap {
    sink: mocks::Sink,
    log: Arc<Mutex<Vec<u8>>>,
}

impl Sink for Tap {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let bufs = bufs.into();
        self.log
            .lock()
            .extend_from_slice(bufs.clone().coalesce().as_ref());
        self.sink.send(bufs).await
    }
}

/// Runs a full CUPS connection for `version` and returns every byte each peer wrote.
///
/// The log covers the identity prelude, the handshake messages, and records of every length class
/// in both directions, so it pins both the record format and the SAKE version each CUPS version
/// runs. Ephemeral keys and timestamps come from the deterministic runtime, so a change to its
/// scheduling can also move the log.
fn exchange(seed: u64, version: Version) -> Vec<u8> {
    let runner = deterministic::Runner::new(deterministic::Config::default().with_seed(seed));
    runner.start(|mut context| async move {
        // Start at a seeded time so handshake timestamps have nonzero upper bytes.
        let start = context.random_range(1 << 40..1 << 41);
        context.sleep(Duration::from_millis(start)).await;
        let dialer = PrivateKey::from_seed(context.random());
        let listener = PrivateKey::from_seed(context.random());

        // Connect the peers through sinks that record what each one writes.
        let d2l = Arc::new(Mutex::new(Vec::new()));
        let l2d = Arc::new(Mutex::new(Vec::new()));
        let (dialer_sink, listener_stream) = mocks::Channel::init_with_buffer_size(1 << 20);
        let (listener_sink, dialer_stream) = mocks::Channel::init_with_buffer_size(1 << 20);
        let dialer_sink = Tap {
            sink: dialer_sink,
            log: d2l.clone(),
        };
        let listener_sink = Tap {
            sink: listener_sink,
            log: l2d.clone(),
        };

        // Complete the handshake.
        let listener_handshake = Handshake::new(listener.clone(), version);
        let handle = context.child("listener").spawn(move |context| async move {
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
        let (mut dialer_tx, mut dialer_rx) = Handshake::new(dialer, version)
            .dial(
                context.child("dialer"),
                NAMESPACE,
                MAX_MESSAGE_SIZE,
                listener.public_key(),
                dialer_stream,
                dialer_sink,
            )
            .await
            .unwrap();
        let (_, mut listener_tx, mut listener_rx) = handle.await.unwrap().unwrap();

        // Send one record of each length class in each direction.
        for lengths in LENGTHS {
            let mut message = vec![0u8; context.random_range(lengths.clone())];
            context.fill(&mut message[..]);
            dialer_tx.send(message.clone()).await.unwrap();
            assert_eq!(
                listener_rx.recv().await.unwrap().coalesce(),
                message.as_slice()
            );

            let mut message = vec![0u8; context.random_range(lengths)];
            context.fill(&mut message[..]);
            listener_tx.send(message.clone()).await.unwrap();
            assert_eq!(
                dialer_rx.recv().await.unwrap().coalesce(),
                message.as_slice()
            );
        }

        // Keep the directions apart so the log does not depend on how the peers' writes interleave.
        let mut log = d2l.lock().clone();
        log.extend_from_slice(&l2d.lock());
        log
    })
}

struct CupsV0;

impl Conformance for CupsV0 {
    async fn commit(seed: u64) -> Vec<u8> {
        exchange(seed, Version::V0)
    }
}

struct CupsV1;

impl Conformance for CupsV1 {
    async fn commit(seed: u64) -> Vec<u8> {
        exchange(seed, Version::V1)
    }
}

conformance_tests! {
    CupsV0 => 256,
    CupsV1 => 256,
}
