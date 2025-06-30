#![no_main]

use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt as _, Signer};
use commonware_runtime::{deterministic, mocks, Metrics, Runner, Spawner};
use commonware_stream::{
    public_key::{Config, Connection, IncomingConnection},
    Receiver as _, Sender as _,
};
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
        let max_message_size = u.int_in_range(177..=1024 * 1023)?;
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

fuzz_target!(|input: FuzzInput| {
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
            crypto: dialer_crypto.clone(),
            namespace: input.namespace.clone(),
            max_message_size,
            synchrony_bound,
            max_handshake_age,
            handshake_timeout,
        };

        let listener_config = Config {
            crypto: listener_crypto.clone(),
            namespace: input.namespace.clone(),
            max_message_size,
            synchrony_bound,
            max_handshake_age,
            handshake_timeout,
        };

        let listener_handle = context.with_label("listener").spawn({
            move |context| async move {
                let incoming = IncomingConnection::verify(
                    &context,
                    listener_config,
                    listener_sink,
                    listener_stream,
                )
                .await?;
                Connection::upgrade_listener(context, incoming).await
            }
        });

        let dialer_result = Connection::upgrade_dialer(
            context.clone(),
            dialer_config,
            dialer_sink,
            dialer_stream,
            listener_crypto.public_key(),
        )
        .await
        .unwrap();

        let dialer_connection = dialer_result;
        let listener_connection = listener_handle.await.unwrap().unwrap();
        let (mut dialer_sender, mut dialer_receiver) = dialer_connection.split();
        let (mut listener_sender, mut listener_receiver) = listener_connection.split();

        // Exchange messages from dialer to listener
        for (i, msg) in input.messages_to_listener.iter().enumerate() {
            if msg.is_empty() || msg.len() > max_message_size {
                continue;
            }

            dialer_sender.send(msg).await.unwrap();
            let received = listener_receiver.receive().await.unwrap();
            assert_eq!(&received[..], &msg[..], "Message {i} mismatch");
        }

        // Exchange messages from listener to dialer
        for (i, msg) in input.messages_to_dialer.iter().enumerate() {
            if msg.is_empty() || msg.len() > max_message_size {
                continue;
            }

            listener_sender.send(msg).await.unwrap();
            let received = dialer_receiver.receive().await.unwrap();
            assert_eq!(&received[..], &msg[..], "Message {i} mismatch");
        }
    });
});
