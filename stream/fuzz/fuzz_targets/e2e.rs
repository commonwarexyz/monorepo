#![no_main]

use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt as _, Signer};
use commonware_runtime::{deterministic, mocks, Clock, Runner};
use commonware_stream::{
    public_key::{
        handshake::{Hello, Info},
        x25519, Config, Connection, IncomingConnection,
    },
    utils::codec::{recv_frame, send_frame},
};
use commonware_utils::SystemTimeExt;
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
enum StateAction {
    SendValidHello,
    SendInvalidHello,
    SendInvalidConfirmation,
    SendRandomData,
    CloseConnection,
    ReceiveMessage,
    AttemptUpgrade,
}

impl<'a> arbitrary::Arbitrary<'a> for StateAction {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let action = u.int_in_range(0..=6)?;
        Ok(match action {
            0 => StateAction::SendValidHello,
            1 => StateAction::SendInvalidHello,
            2 => StateAction::SendInvalidConfirmation,
            3 => StateAction::SendRandomData,
            4 => StateAction::CloseConnection,
            5 => StateAction::ReceiveMessage,
            _ => StateAction::AttemptUpgrade,
        })
    }
}

#[derive(Debug)]
pub struct FuzzInput {
    // Cryptographic setup
    dialer_seed: u64,
    listener_seed: u64,

    // Protocol configuration
    namespace: Vec<u8>,
    max_message_size: usize,
    synchrony_bound_secs: u64,
    max_handshake_age_secs: u64,
    handshake_timeout_secs: u64,

    // State machine actions
    dialer_actions: Vec<StateAction>,
    listener_actions: Vec<StateAction>,

    // Corruption data for invalid messages
    corrupt_hello_data: Vec<u8>,
    corrupt_confirmation_data: Vec<u8>,
    random_data: Vec<u8>,

    // Timing parameters
    corrupt_timestamp: u64,
    corrupt_ephemeral_key: [u8; 32],

    // Wrong peer key for invalid scenarios
    wrong_peer_seed: u64,
}

impl<'a> arbitrary::Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let dialer_seed = u64::arbitrary(u)?;
        let listener_seed = dialer_seed.wrapping_add(1);
        let wrong_peer_seed = dialer_seed.wrapping_add(2);

        let namespace_len = u.int_in_range(0..=64)?;
        let namespace = (0..namespace_len)
            .map(|_| u8::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        let max_message_size = u.int_in_range(150..=8192)?;
        let synchrony_bound_secs = u.int_in_range(1..=10)?;
        let max_handshake_age_secs = u.int_in_range(1..=10)?;
        let handshake_timeout_secs = u.int_in_range(1..=10)?;

        let num_dialer_actions = u.int_in_range(1..=8)?;
        let dialer_actions = (0..num_dialer_actions)
            .map(|_| StateAction::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        let num_listener_actions = u.int_in_range(1..=8)?;
        let listener_actions = (0..num_listener_actions)
            .map(|_| StateAction::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        let corrupt_hello_len = u.int_in_range(0..=512)?;
        let corrupt_hello_data = (0..corrupt_hello_len)
            .map(|_| u8::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        let corrupt_confirmation_len = u.int_in_range(0..=512)?;
        let corrupt_confirmation_data = (0..corrupt_confirmation_len)
            .map(|_| u8::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        let random_data_len = u.int_in_range(0..=1024)?;
        let random_data = (0..random_data_len)
            .map(|_| u8::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        let corrupt_timestamp = u64::arbitrary(u)?;
        let corrupt_ephemeral_key = u.arbitrary::<[u8; 32]>()?;

        Ok(FuzzInput {
            dialer_seed,
            listener_seed,
            namespace,
            max_message_size,
            synchrony_bound_secs,
            max_handshake_age_secs,
            handshake_timeout_secs,
            dialer_actions,
            listener_actions,
            corrupt_hello_data,
            corrupt_confirmation_data,
            random_data,
            corrupt_timestamp,
            corrupt_ephemeral_key,
            wrong_peer_seed,
        })
    }
}

#[derive(Debug, Clone)]
enum ProtocolState {
    Initial,
    WaitingForHello,
    WaitingForResponse,
    WaitingForConfirmation,
    Failed,
    Upgraded,
}

struct StateMachine {
    state: ProtocolState,
    crypto: PrivateKey,
    config: Config<PrivateKey>,
    is_dialer: bool,
}

impl StateMachine {
    fn new(crypto: PrivateKey, config: Config<PrivateKey>, is_dialer: bool) -> Self {
        Self {
            state: if is_dialer {
                ProtocolState::Initial
            } else {
                ProtocolState::WaitingForHello
            },
            crypto,
            config,
            is_dialer,
        }
    }

    fn transition_to(&mut self, new_state: ProtocolState) {
        self.state = new_state;
    }

    fn is_valid_transition(&self, action: StateAction, peer_has_sent_messages: bool) -> bool {
        // First check ReceiveMessage availability regardless of state
        if action == StateAction::ReceiveMessage {
            return peer_has_sent_messages;
        }

        match (&self.state, action, self.is_dialer) {
            // Dialer states and actions
            (ProtocolState::Initial, StateAction::AttemptUpgrade, true) => true,
            (ProtocolState::Initial, StateAction::SendValidHello, true) => true,
            (ProtocolState::Initial, StateAction::SendInvalidHello, true) => true,
            // We only model sending valid confirmations during StateAction::AttemptUpgrade.
            (ProtocolState::WaitingForResponse, StateAction::SendInvalidConfirmation, true) => true,

            // Listener states and actions
            (ProtocolState::Initial, StateAction::AttemptUpgrade, false) => true,
            (ProtocolState::WaitingForHello, StateAction::SendValidHello, false) => true,
            (ProtocolState::WaitingForHello, StateAction::SendInvalidHello, false) => true,
            // We only model sending valid confirmations during StateAction::AttemptUpgrade.
            (ProtocolState::WaitingForHello, StateAction::SendInvalidConfirmation, false) => true,

            // Universal actions valid from any state
            (_, StateAction::SendRandomData, _) => true,
            (_, StateAction::CloseConnection, _) => true,

            // Everything else is invalid
            _ => false,
        }
    }
}

fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::default();
    executor.start(|mut context| async move {
        let dialer_crypto = PrivateKey::from_seed(input.dialer_seed);
        let listener_crypto = PrivateKey::from_seed(input.listener_seed);
        let wrong_peer_crypto = PrivateKey::from_seed(input.wrong_peer_seed);

        let synchrony_bound = Duration::from_secs(input.synchrony_bound_secs);
        let max_handshake_age = Duration::from_secs(input.max_handshake_age_secs);
        let handshake_timeout = Duration::from_secs(input.handshake_timeout_secs);

        let dialer_config = Config {
            crypto: dialer_crypto.clone(),
            namespace: input.namespace.clone(),
            max_message_size: input.max_message_size,
            synchrony_bound,
            max_handshake_age,
            handshake_timeout,
        };

        let listener_config = Config {
            crypto: listener_crypto.clone(),
            namespace: input.namespace.clone(),
            max_message_size: input.max_message_size,
            synchrony_bound,
            max_handshake_age,
            handshake_timeout,
        };

        let (dialer_sink, listener_stream) = mocks::Channel::init();
        let (listener_sink, dialer_stream) = mocks::Channel::init();

        let mut dialer_state =
            StateMachine::new(dialer_crypto.clone(), dialer_config.clone(), true);

        let mut listener_state =
            StateMachine::new(listener_crypto.clone(), listener_config.clone(), false);

        let mut dialer_sink = dialer_sink;
        let mut listener_sink = listener_sink;
        let mut dialer_stream = dialer_stream;
        let mut listener_stream = listener_stream;

        let mut pending_dialer_to_listener_messages: u32 = 0;
        let mut pending_listener_to_dialer_messages: u32 = 0;

        let max_actions = input.dialer_actions.len().max(input.listener_actions.len());

        for i in 0..max_actions {
            if let Some(action) = input.dialer_actions.get(i) {
                if dialer_state
                    .is_valid_transition(*action, pending_listener_to_dialer_messages > 0)
                {
                    match action {
                        StateAction::SendValidHello => {
                            let ephemeral_secret = x25519::new(&mut context);
                            let ephemeral_public_key =
                                x25519::PublicKey::from_secret(&ephemeral_secret);
                            let hello = Hello::sign(
                                &mut dialer_state.crypto.clone(),
                                &dialer_state.config.namespace,
                                Info::new(
                                    listener_crypto.public_key(),
                                    ephemeral_public_key,
                                    context.current().epoch_millis(),
                                ),
                            );
                            match send_frame(
                                &mut dialer_sink,
                                &hello.encode(),
                                input.max_message_size,
                            )
                            .await
                            {
                                Ok(()) => {
                                    pending_dialer_to_listener_messages += 1;
                                    dialer_state.transition_to(ProtocolState::WaitingForResponse);
                                }
                                Err(_) => dialer_state.transition_to(ProtocolState::Failed),
                            }
                        }
                        StateAction::SendInvalidHello => {
                            if !input.corrupt_hello_data.is_empty() {
                                if send_frame(
                                    &mut dialer_sink,
                                    &input.corrupt_hello_data,
                                    input.max_message_size,
                                )
                                .await
                                .is_ok()
                                {
                                    pending_dialer_to_listener_messages += 1;
                                }
                                dialer_state.transition_to(ProtocolState::Failed);
                            } else {
                                let wrong_peer = wrong_peer_crypto.public_key();
                                let ephemeral_public_key =
                                    x25519::PublicKey::from_bytes(input.corrupt_ephemeral_key);
                                let hello = Hello::sign(
                                    &mut dialer_state.crypto.clone(),
                                    &dialer_state.config.namespace,
                                    Info::new(
                                        wrong_peer,
                                        ephemeral_public_key,
                                        input.corrupt_timestamp,
                                    ),
                                );
                                if send_frame(
                                    &mut dialer_sink,
                                    &hello.encode(),
                                    input.max_message_size,
                                )
                                .await
                                .is_ok()
                                {
                                    pending_dialer_to_listener_messages += 1;
                                }
                            }
                            dialer_state.transition_to(ProtocolState::Failed);
                        }
                        StateAction::SendInvalidConfirmation => {
                            if send_frame(
                                &mut dialer_sink,
                                &input.corrupt_confirmation_data,
                                input.max_message_size,
                            )
                            .await
                            .is_ok()
                            {
                                pending_dialer_to_listener_messages += 1;
                            }
                            dialer_state.transition_to(ProtocolState::Failed);
                        }
                        StateAction::SendRandomData => {
                            if send_frame(
                                &mut dialer_sink,
                                &input.random_data,
                                input.max_message_size,
                            )
                            .await
                            .is_ok()
                            {
                                pending_dialer_to_listener_messages += 1;
                            }
                        }
                        StateAction::ReceiveMessage => {
                            pending_listener_to_dialer_messages =
                                pending_listener_to_dialer_messages
                                    .checked_sub(1)
                                    .expect("ReceiveMessage but no peer frame is pending");

                            match recv_frame(&mut dialer_stream, input.max_message_size).await {
                                Ok(msg) => {
                                    if let Ok(hello) = Hello::decode(msg.as_ref()) {
                                        let verify_result = hello.verify(
                                            &context,
                                            &dialer_state.config.crypto.public_key(),
                                            &dialer_state.config.namespace,
                                            dialer_state.config.synchrony_bound,
                                            dialer_state.config.max_handshake_age,
                                        );

                                        match verify_result {
                                            Ok(()) => {
                                                if matches!(
                                                    dialer_state.state,
                                                    ProtocolState::WaitingForResponse
                                                ) {
                                                    dialer_state.transition_to(
                                                        ProtocolState::WaitingForConfirmation,
                                                    );
                                                }
                                            }
                                            Err(_) => {
                                                dialer_state.transition_to(ProtocolState::Failed);
                                            }
                                        }
                                    }
                                }
                                Err(_) => {
                                    dialer_state.transition_to(ProtocolState::Failed);
                                }
                            }
                        }
                        StateAction::AttemptUpgrade => {
                            let upgrade_context = context.clone();
                            match Connection::upgrade_dialer(
                                upgrade_context,
                                dialer_config.clone(),
                                dialer_sink,
                                dialer_stream,
                                listener_crypto.public_key(),
                            )
                            .await
                            {
                                Ok(_connection) => {
                                    dialer_state.transition_to(ProtocolState::Upgraded);
                                    return;
                                }
                                Err(_) => {
                                    dialer_state.transition_to(ProtocolState::Failed);
                                    return;
                                }
                            }
                        }
                        StateAction::CloseConnection => {
                            drop(dialer_sink);
                            return;
                        }
                    }
                }
            }

            if let Some(action) = input.listener_actions.get(i) {
                if listener_state
                    .is_valid_transition(*action, pending_dialer_to_listener_messages > 0)
                {
                    match action {
                        StateAction::SendValidHello => {
                            let ephemeral_secret = x25519::new(&mut context);
                            let ephemeral_public_key =
                                x25519::PublicKey::from_secret(&ephemeral_secret);
                            let hello = Hello::sign(
                                &mut listener_state.crypto.clone(),
                                &listener_state.config.namespace,
                                Info::new(
                                    dialer_crypto.public_key(),
                                    ephemeral_public_key,
                                    context.current().epoch_millis(),
                                ),
                            );
                            match send_frame(
                                &mut listener_sink,
                                &hello.encode(),
                                input.max_message_size,
                            )
                            .await
                            {
                                Ok(()) => {
                                    pending_listener_to_dialer_messages += 1;
                                    listener_state
                                        .transition_to(ProtocolState::WaitingForConfirmation);
                                }
                                Err(_) => listener_state.transition_to(ProtocolState::Failed),
                            }
                        }
                        StateAction::SendInvalidHello => {
                            if !input.corrupt_hello_data.is_empty() {
                                if send_frame(
                                    &mut listener_sink,
                                    &input.corrupt_hello_data,
                                    input.max_message_size,
                                )
                                .await
                                .is_ok()
                                {
                                    pending_listener_to_dialer_messages += 1;
                                }
                                listener_state.transition_to(ProtocolState::Failed);
                            } else {
                                let wrong_peer = wrong_peer_crypto.public_key();
                                let ephemeral_public_key =
                                    x25519::PublicKey::from_bytes(input.corrupt_ephemeral_key);
                                let hello = Hello::sign(
                                    &mut listener_state.crypto.clone(),
                                    &listener_state.config.namespace,
                                    Info::new(
                                        wrong_peer,
                                        ephemeral_public_key,
                                        input.corrupt_timestamp,
                                    ),
                                );
                                if send_frame(
                                    &mut listener_sink,
                                    &hello.encode(),
                                    input.max_message_size,
                                )
                                .await
                                .is_ok()
                                {
                                    pending_listener_to_dialer_messages += 1;
                                }
                            }
                            listener_state.transition_to(ProtocolState::Failed);
                        }
                        StateAction::SendInvalidConfirmation => {
                            if send_frame(
                                &mut listener_sink,
                                &input.corrupt_confirmation_data,
                                input.max_message_size,
                            )
                            .await
                            .is_ok()
                            {
                                pending_listener_to_dialer_messages += 1;
                            }
                            listener_state.transition_to(ProtocolState::Failed);
                        }
                        StateAction::SendRandomData => {
                            if send_frame(
                                &mut listener_sink,
                                &input.random_data,
                                input.max_message_size,
                            )
                            .await
                            .is_ok()
                            {
                                pending_listener_to_dialer_messages += 1;
                            }
                        }
                        StateAction::ReceiveMessage => {
                            pending_dialer_to_listener_messages =
                                pending_dialer_to_listener_messages
                                    .checked_sub(1)
                                    .expect("ReceiveMessage but no peer frame is pending");

                            match recv_frame(&mut listener_stream, input.max_message_size).await {
                                Ok(msg) => {
                                    if let Ok(hello) = Hello::decode(msg.as_ref()) {
                                        let verify_result = hello.verify(
                                            &context,
                                            &listener_state.config.crypto.public_key(),
                                            &listener_state.config.namespace,
                                            listener_state.config.synchrony_bound,
                                            listener_state.config.max_handshake_age,
                                        );

                                        match verify_result {
                                            Ok(()) => {
                                                if matches!(
                                                    listener_state.state,
                                                    ProtocolState::WaitingForHello
                                                ) {
                                                    listener_state.transition_to(
                                                        ProtocolState::WaitingForConfirmation,
                                                    );
                                                }
                                            }
                                            Err(_) => {
                                                listener_state.transition_to(ProtocolState::Failed);
                                            }
                                        }
                                    }
                                }
                                Err(_) => {
                                    listener_state.transition_to(ProtocolState::Failed);
                                }
                            }
                        }
                        StateAction::AttemptUpgrade => {
                            let verify_context = context.clone();
                            match IncomingConnection::verify(
                                &verify_context,
                                listener_config.clone(),
                                listener_sink,
                                listener_stream,
                            )
                            .await
                            {
                                Ok(incoming) => {
                                    let upgrade_context = context.clone();
                                    match Connection::upgrade_listener(upgrade_context, incoming)
                                        .await
                                    {
                                        Ok(_connection) => {
                                            listener_state.transition_to(ProtocolState::Upgraded);
                                            return;
                                        }
                                        Err(_) => {
                                            listener_state.transition_to(ProtocolState::Failed);
                                            return;
                                        }
                                    }
                                }
                                Err(_) => {
                                    listener_state.transition_to(ProtocolState::Failed);
                                    return;
                                }
                            }
                        }
                        StateAction::CloseConnection => {
                            drop(listener_sink);
                            return;
                        }
                    }
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
