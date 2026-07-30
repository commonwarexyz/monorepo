#![cfg(target_arch = "wasm32")]

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit as _,
    aead::{Aead as _, Payload},
};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{Signer as _, ed25519};
use commonware_math::algebra::Random as _;
use commonware_p2p::authenticated::lookup::{
    AttachmentConfig, AttachmentNetwork, PeerAdmission, Rejected,
};
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{ConnectionInfo, IoBuf, Quota, web::Runtime};
use commonware_stream::encrypted;
use commonware_utils::{NZUsize, sys_rng};
use commonware_webrtc::{WebRtcConfig, WebRtcConnection, WebRtcOrigin};
use futures::channel::oneshot;
use hmac::{Hmac, Mac as _};
use js_sys::{Date, Function, Object, Promise, Reflect};
use sha2::Sha256;
use std::{cell::RefCell, num::NonZeroU32, rc::Rc, time::Duration};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use web_sys::{RtcDataChannel, RtcPeerConnection};

const CHAT_CHANNEL: u64 = 0;
const CHAT_NAMESPACE: &[u8] = b"_COMMONWARE_BROWSER_P2P_CHAT";
const MAX_CHAT_MESSAGE_SIZE: usize = 16 * 1024;
const MAX_NETWORK_MESSAGE_SIZE: u32 = 64 * 1024;
const CHANNEL_BACKLOG: usize = 128;
const SIGNALING_INFO: &[u8] = b"commonware-browser-p2p-signaling-v1";

type ChatSender = commonware_p2p::authenticated::lookup::Sender<
    ed25519::PublicKey,
    commonware_runtime::web::Context<()>,
>;

struct State {
    runtime: Option<Runtime<()>>,
    connection: Option<WebRtcConnection>,
    sender: Option<ChatSender>,
    peer: Option<ed25519::PublicKey>,
    generation: u64,
}

impl State {
    const fn new() -> Self {
        Self {
            runtime: None,
            connection: None,
            sender: None,
            peer: None,
            generation: 0,
        }
    }

    fn stop(&mut self) -> bool {
        let was_running = self.runtime.is_some();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown(0);
        }
        self.connection = None;
        self.sender = None;
        self.peer = None;
        self.generation = self.generation.wrapping_add(1);
        was_running
    }
}

/// Browser-owned authenticated chat session.
#[wasm_bindgen]
pub struct BrowserChat {
    private_key: ed25519::PrivateKey,
    public_key: String,
    on_event: Rc<Function>,
    state: Rc<RefCell<State>>,
}

#[wasm_bindgen]
impl BrowserChat {
    /// Return the session's ephemeral Ed25519 public key.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> String {
        self.public_key.clone()
    }

    /// Create a signaling cipher that works outside browser secure contexts.
    #[wasm_bindgen(js_name = createSignalingCipher)]
    pub fn create_signaling_cipher(
        &self,
        session: &[u8],
        secret: &[u8],
    ) -> Result<SignalingCipher, JsValue> {
        SignalingCipher::new(session, secret)
    }

    /// Attach an established WebRTC data channel to the authenticated chat network.
    pub fn prepare(
        &self,
        peer_connection: RtcPeerConnection,
        data_channel: RtcDataChannel,
    ) -> Result<(), JsValue> {
        let connection =
            WebRtcConnection::new(peer_connection, data_channel, WebRtcConfig::default())
                .map_err(|_| JsValue::from_str("Could not initialize the WebRTC transport."))?;
        let mut state = self.state.borrow_mut();
        if state.runtime.is_some() || state.connection.is_some() {
            return Err(JsValue::from_str("A WebRTC transport is already prepared."));
        }
        state.connection = Some(connection);
        Ok(())
    }

    /// Start the Commonware handshake after both browser adapters are ready.
    pub fn attach(&self, expected_peer_hex: String, outbound: bool) -> Promise {
        let expected_peer = match parse_public_key(&expected_peer_hex) {
            Ok(peer) => peer,
            Err(message) => return rejected_promise(message),
        };

        emit_connection(&self.on_event, "connecting");

        let connection = match self.state.borrow_mut().connection.take() {
            Some(connection) => connection,
            None => return self.reject_attach("The WebRTC transport is not prepared."),
        };

        let runtime = match Runtime::new() {
            Ok(runtime) => runtime,
            Err(_) => return self.reject_attach("Could not initialize the browser runtime."),
        };
        let generation = {
            let mut state = self.state.borrow_mut();
            state.runtime = Some(runtime.clone());
            state.generation
        };
        let state = Rc::clone(&self.state);
        let on_event = Rc::clone(&self.on_event);
        let private_key = self.private_key.clone();
        let (result_sender, result_receiver) = oneshot::channel();

        runtime.spawn_root(move |context| async move {
            let config = attachment_config(private_key, expected_peer.clone());
            let (mut network, _oracle, attachments) =
                AttachmentNetwork::<_, _, WebRtcConnection, ExactPeerAdmission>::new(
                    context, config,
                );
            let (sender, mut receiver) = network.register(
                CHAT_CHANNEL,
                Quota::per_second(NonZeroU32::new(32).expect("non-zero quota")),
                CHANNEL_BACKLOG,
            );
            let _network = network.start();

            let attached = if outbound {
                attachments
                    .attach_outbound(expected_peer.clone(), connection)
                    .await
            } else {
                attachments.attach_inbound(connection).await
            };
            if attached.is_err() {
                fail_attach(&state, generation, &on_event, result_sender);
                return;
            }

            if !is_current(&state, generation) {
                let _ = result_sender.send(Err("Connection was canceled."));
                return;
            }
            {
                let mut current = state.borrow_mut();
                current.sender = Some(sender);
                current.peer = Some(expected_peer.clone());
            }
            emit_peer(&on_event, &expected_peer.to_string());
            emit_connection(&on_event, "connected");
            let _ = result_sender.send(Ok(()));

            let mut next_message_id = 0_u64;
            while let Ok((sender, message)) = receiver.recv().await {
                if sender != expected_peer {
                    emit_error(
                        &on_event,
                        "Ignored a message from an unexpected peer.",
                        false,
                    );
                    continue;
                }
                let bytes = message.as_ref();
                if bytes.len() > MAX_CHAT_MESSAGE_SIZE {
                    emit_error(&on_event, "Ignored an oversized chat message.", false);
                    continue;
                }
                let Ok(text) = std::str::from_utf8(bytes) else {
                    emit_error(&on_event, "Ignored a non-UTF-8 chat message.", false);
                    continue;
                };
                next_message_id = next_message_id.wrapping_add(1);
                emit_message(
                    &on_event,
                    &format!("{generation}-{next_message_id}"),
                    &sender.to_string(),
                    text,
                );
            }

            if stop_generation(&state, generation) {
                emit_error(&on_event, "The authenticated connection closed.", false);
                emit_connection(&on_event, "disconnected");
            }
        });

        future_to_promise(async move {
            match result_receiver.await {
                Ok(Ok(())) => Ok(JsValue::UNDEFINED),
                Ok(Err(message)) => Err(JsValue::from_str(message)),
                Err(_) => Err(JsValue::from_str("Connection was canceled.")),
            }
        })
    }

    /// Send one UTF-8 chat message through the authenticated lookup sender.
    pub fn send(&self, text: String) -> Promise {
        let result = send_message(&self.state, text);
        future_to_promise(async move {
            result
                .map(|()| JsValue::UNDEFINED)
                .map_err(JsValue::from_str)
        })
    }

    /// Stop the runtime and close the active transport.
    pub fn disconnect(&self) {
        self.stop(true);
    }
}

/// Authenticated encryption for the short-lived rendezvous transcript.
#[wasm_bindgen]
pub struct SignalingCipher {
    cipher: ChaCha20Poly1305,
}

#[wasm_bindgen]
impl SignalingCipher {
    fn new(session: &[u8], secret: &[u8]) -> Result<Self, JsValue> {
        if session.len() != 32 || secret.len() != 32 {
            return Err(JsValue::from_str("The signaling key material is invalid."));
        }

        let mut extract = Hmac::<Sha256>::new_from_slice(session)
            .map_err(|_| JsValue::from_str("Could not derive the signaling key."))?;
        extract.update(secret);
        let pseudorandom_key = extract.finalize().into_bytes();

        let mut expand = Hmac::<Sha256>::new_from_slice(&pseudorandom_key)
            .map_err(|_| JsValue::from_str("Could not derive the signaling key."))?;
        expand.update(SIGNALING_INFO);
        expand.update(&[1]);
        let key = expand.finalize().into_bytes();

        Ok(Self {
            cipher: ChaCha20Poly1305::new((&key).into()),
        })
    }

    /// Encrypt and authenticate one signaling payload.
    pub fn seal(
        &self,
        nonce: &[u8],
        additional_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| JsValue::from_str("The signaling nonce is invalid."))?;
        self.cipher
            .encrypt(
                nonce.into(),
                Payload {
                    msg: plaintext,
                    aad: additional_data,
                },
            )
            .map_err(|_| JsValue::from_str("Could not encrypt the signaling message."))
    }

    /// Authenticate and decrypt one signaling payload.
    pub fn open(
        &self,
        nonce: &[u8],
        additional_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let nonce: &[u8; 12] = nonce
            .try_into()
            .map_err(|_| JsValue::from_str("The signaling nonce is invalid."))?;
        self.cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: additional_data,
                },
            )
            .map_err(|_| JsValue::from_str("The signaling message could not be authenticated."))
    }
}

impl BrowserChat {
    fn stop(&self, emit: bool) {
        let stopped = self.state.borrow_mut().stop();
        if emit && stopped {
            emit_connection(&self.on_event, "disconnected");
        }
    }

    fn reject_attach(&self, message: &'static str) -> Promise {
        emit_error(&self.on_event, message, true);
        emit_connection(&self.on_event, "disconnected");
        rejected_promise(message)
    }
}

impl Drop for BrowserChat {
    fn drop(&mut self) {
        self.state.borrow_mut().stop();
    }
}

/// Create a session with a fresh ephemeral Ed25519 identity.
#[wasm_bindgen(js_name = createBrowserChat)]
pub fn create_browser_chat(on_event: Function) -> BrowserChat {
    let private_key = ed25519::PrivateKey::random(sys_rng());
    let public_key = private_key.public_key().to_string();
    BrowserChat {
        private_key,
        public_key,
        on_event: Rc::new(on_event),
        state: Rc::new(RefCell::new(State::new())),
    }
}

#[derive(Clone)]
struct ExactPeerAdmission {
    expected_peer: ed25519::PublicKey,
}

impl PeerAdmission<ed25519::PublicKey, WebRtcOrigin> for ExactPeerAdmission {
    type Permit = ();

    fn pre_auth(&self, _info: &ConnectionInfo<WebRtcOrigin>) -> Result<Self::Permit, Rejected> {
        Ok(())
    }

    async fn post_auth(
        &self,
        _permit: Self::Permit,
        peer: &ed25519::PublicKey,
        _info: &ConnectionInfo<WebRtcOrigin>,
    ) -> Result<(), Rejected> {
        if peer != &self.expected_peer {
            return Err(Rejected);
        }
        Ok(())
    }
}

fn attachment_config(
    private_key: ed25519::PrivateKey,
    expected_peer: ed25519::PublicKey,
) -> AttachmentConfig<ed25519::PrivateKey, ExactPeerAdmission> {
    AttachmentConfig {
        stream: encrypted::Config {
            signing_key: private_key,
            namespace: CHAT_NAMESPACE.to_vec(),
            max_message_size: MAX_NETWORK_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        },
        admission: ExactPeerAdmission { expected_peer },
        mailbox_size: NZUsize!(128),
        send_batch_size: NZUsize!(8),
        ping_frequency: Duration::from_secs(30),
        tracked_peer_sets: NZUsize!(1),
        peer_connection_cooldown: Duration::ZERO,
        block_duration: Duration::from_secs(60),
    }
}

fn parse_public_key(value: &str) -> Result<ed25519::PublicKey, &'static str> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Expected peer must be a 32-byte hex Ed25519 key.");
    }
    let bytes = commonware_formatting::from_hex(value)
        .ok_or("Expected peer must be a 32-byte hex Ed25519 key.")?;
    ed25519::PublicKey::decode(bytes.as_slice())
        .map_err(|_| "Expected peer must be a 32-byte hex Ed25519 key.")
}

fn send_message(state: &RefCell<State>, text: String) -> Result<(), &'static str> {
    if text.is_empty() {
        return Err("Chat messages cannot be empty.");
    }
    if text.len() > MAX_CHAT_MESSAGE_SIZE {
        return Err("Chat messages cannot exceed 16 KiB.");
    }
    let (mut sender, peer) = {
        let current = state.borrow();
        let sender = current.sender.clone().ok_or("The chat is not connected.")?;
        let peer = current.peer.clone().ok_or("The chat is not connected.")?;
        (sender, peer)
    };
    let recipients = sender.send(Recipients::One(peer), IoBuf::from(text.into_bytes()), false);
    if recipients.is_empty() {
        return Err("The chat message was rejected by local backpressure.");
    }
    Ok(())
}

fn fail_attach(
    state: &RefCell<State>,
    generation: u64,
    on_event: &Function,
    result_sender: oneshot::Sender<Result<(), &'static str>>,
) {
    let message = "Could not authenticate the expected peer.";
    if !stop_generation(state, generation) {
        let _ = result_sender.send(Err("Connection was canceled."));
        return;
    }
    emit_error(on_event, message, true);
    emit_connection(on_event, "disconnected");
    let _ = result_sender.send(Err(message));
}

fn is_current(state: &RefCell<State>, generation: u64) -> bool {
    state.borrow().generation == generation
}

fn stop_generation(state: &RefCell<State>, generation: u64) -> bool {
    let mut current = state.borrow_mut();
    if current.generation != generation {
        return false;
    }
    current.stop();
    true
}

fn rejected_promise(message: &str) -> Promise {
    Promise::reject(&JsValue::from_str(message))
}

fn event(event_type: &str) -> Object {
    let event = Object::new();
    set(&event, "type", &JsValue::from_str(event_type));
    event
}

fn emit_connection(on_event: &Function, state: &str) {
    let event = event("connection");
    set(&event, "state", &JsValue::from_str(state));
    emit(on_event, &event);
}

fn emit_peer(on_event: &Function, public_key: &str) {
    let event = event("peer");
    set(&event, "publicKey", &JsValue::from_str(public_key));
    emit(on_event, &event);
}

fn emit_message(on_event: &Function, id: &str, sender: &str, text: &str) {
    let event = event("message");
    set(&event, "id", &JsValue::from_str(id));
    set(&event, "sender", &JsValue::from_str(sender));
    set(&event, "text", &JsValue::from_str(text));
    set(&event, "receivedAt", &JsValue::from_f64(Date::now()));
    emit(on_event, &event);
}

fn emit_error(on_event: &Function, message: &str, recoverable: bool) {
    let event = event("error");
    set(&event, "message", &JsValue::from_str(message));
    set(&event, "recoverable", &JsValue::from_bool(recoverable));
    emit(on_event, &event);
}

fn set(event: &Object, key: &str, value: &JsValue) {
    let _ = Reflect::set(event, &JsValue::from_str(key), value);
}

fn emit(on_event: &Function, event: &Object) {
    let _ = on_event.call1(&JsValue::UNDEFINED, event);
}
