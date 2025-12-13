#![no_main]

use commonware_cryptography::{ed25519::PrivateKey, Signer};
use commonware_runtime::{deterministic, mocks, Metrics, Runner, Spawner};
use commonware_stream::{dial, listen, Config};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

#[derive(Debug)]
pub struct FuzzInput {
    // Seeds for cryptographic identities
    dialer_seed: u64,
    listener_seed: u64,

    // Configuration parameters
    namespace: Vec<u8>,
    max_message_size: usize,
    synchrony_bound_secs: u64,
    max_handshake_age_secs: u64,
    handshake_timeout_secs: u64,

    // Messages to exchange
    messages_to_listener: Vec<Vec<u8>>,
    messages_to_dialer: Vec<Vec<u8>>,
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate basic seeds
        let dialer_seed = u64::arbitrary(u)?;
        let listener_seed = dialer_seed.wrapping_add(1);

        // Generate namespace (reasonable size)
        let namespace_len = u.int_in_range(0..=256)?;
        let namespace = (0..namespace_len)
            .map(|_| u8::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        // Generate constrained parameters
        // 210 is enough to contain the largest message.
        let max_message_size = u.int_in_range(210..=1024 * 1023)?;
        let synchrony_bound_secs = u.int_in_range(1..=12)?;
        let max_handshake_age_secs = u.int_in_range(1..=12)?;
        let handshake_timeout_secs = u.int_in_range(1..=12)?;

        // Generate messages with size constraints
        let num_messages_to_listener = u.int_in_range(0..=10)?; // Reasonable number of messages
        let mut messages_to_listener = Vec::new();
        for _ in 0..num_messages_to_listener {
            let msg_len = u.int_in_range(0..=max_message_size)?;
            let msg = (0..msg_len)
                .map(|_| u8::arbitrary(u))
                .collect::<Result<Vec<_>, _>>()?;
            messages_to_listener.push(msg);
        }

        let num_messages_to_dialer = u.int_in_range(0..=10)?;
        let mut messages_to_dialer = Vec::new();
        for _ in 0..num_messages_to_dialer {
            let msg_len = u.int_in_range(0..=max_message_size)?;
            let msg = (0..msg_len)
                .map(|_| u8::arbitrary(u))
                .collect::<Result<Vec<_>, _>>()?;
            messages_to_dialer.push(msg);
        }

        Ok(FuzzInput {
            dialer_seed,
            listener_seed,
            namespace,
            max_message_size,
            synchrony_bound_secs,
            max_handshake_age_secs,
            handshake_timeout_secs,
            messages_to_listener,
            messages_to_dialer,
        })
    }
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let max_message_size = input.max_message_size;
        let synchrony_bound = Duration::from_secs(input.synchrony_bound_secs);
        let max_handshake_age = Duration::from_secs(input.max_handshake_age_secs);
        let handshake_timeout = Duration::from_secs(input.handshake_timeout_secs);

        let dialer_crypto = PrivateKey::from_seed(input.dialer_seed);
        let listener_crypto = PrivateKey::from_seed(input.listener_seed);

        let (dialer_sink, listener_stream) = mocks::Channel::init();
        let (listener_sink, dialer_stream) = mocks::Channel::init();

        let dialer_config = Config {
            signing_key: dialer_crypto.clone(),
            namespace: input.namespace.clone(),
            max_message_size,
            synchrony_bound,
            max_handshake_age,
            handshake_timeout,
        };

        let listener_config = Config {
            signing_key: listener_crypto.clone(),
            namespace: input.namespace.clone(),
            max_message_size,
            synchrony_bound,
            max_handshake_age,
            handshake_timeout,
        };

        let listener_handle = context.with_label("listener").spawn({
            move |context| async move {
                listen(
                    context,
                    |_| async { true },
                    listener_config,
                    listener_stream,
                    listener_sink,
                )
                .await
            }
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

        // Exchange messages from dialer to listener
        for (i, msg) in input.messages_to_listener.iter().enumerate() {
            if msg.is_empty() || msg.len() > max_message_size {
                continue;
            }

            dialer_sender.send(msg).await.unwrap();
            let received = listener_receiver.recv().await.unwrap();
            assert_eq!(&received[..], &msg[..], "Message {i} mismatch");
        }

        // Exchange messages from listener to dialer
        for (i, msg) in input.messages_to_dialer.iter().enumerate() {
            if msg.is_empty() || msg.len() > max_message_size {
                continue;
            }

            listener_sender.send(msg).await.unwrap();
            let received = dialer_receiver.recv().await.unwrap();
            assert_eq!(&received[..], &msg[..], "Message {i} mismatch");
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
