#![cfg(target_arch = "wasm32")]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{Signer as _, ed25519};
use commonware_math::algebra::Random as _;
use commonware_p2p::authenticated::lookup::{
    AttachmentConfig, AttachmentNetwork, PeerAdmission, Rejected,
};
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{ConnectionInfo, Dialer as _, IoBuf, Quota, web::Runtime};
use commonware_stream::encrypted;
use commonware_utils::{NZUsize, sys_rng};
use commonware_websocket::{
    MAX_ENDPOINT_LEN, WebSocketConnection, WebSocketDialer, WebSocketEndpoint, WebSocketOrigin,
};
use futures::channel::oneshot;
use js_sys::{Date, Function, Object, Promise, Reflect};
use serde::Deserialize;
use std::{cell::RefCell, num::NonZeroU32, rc::Rc, time::Duration};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

const CHAT_CHANNEL: u64 = 0;
const CHAT_NAMESPACE: &[u8] = b"_COMMONWARE_BROWSER_P2P_CHAT";
const MAX_PAIRING_PAYLOAD_SIZE: usize = 4 * 1024;
const MAX_CHAT_MESSAGE_SIZE: usize = 16 * 1024;
const MAX_NETWORK_MESSAGE_SIZE: u32 = 64 * 1024;
const CHANNEL_BACKLOG: usize = 128;

type ChatSender = commonware_p2p::authenticated::lookup::Sender<
    ed25519::PublicKey,
    commonware_runtime::web::Context<WebSocketDialer>,
>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingPayload {
    version: u8,
    desktop_public_key: String,
    websocket_url: String,
    capability: String,
    session_id: String,
    expires_at: u64,
}

struct ValidatedPairing {
    desktop_public_key: ed25519::PublicKey,
    websocket_endpoint: WebSocketEndpoint,
}

struct State {
    runtime: Option<Runtime<WebSocketDialer>>,
    sender: Option<ChatSender>,
    peer: Option<ed25519::PublicKey>,
    generation: u64,
}

impl State {
    const fn new() -> Self {
        Self {
            runtime: None,
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

    /// Connect to the desktop identified by the pairing payload.
    pub fn connect(&self, pairing_payload: String) -> Promise {
        let pairing = match validate_pairing(&pairing_payload) {
            Ok(pairing) => pairing,
            Err(error) => return rejected_promise(error),
        };

        self.stop(false);
        emit_connection(&self.on_event, "connecting");

        let runtime = match Runtime::new() {
            Ok(runtime) => runtime.with_dialer(WebSocketDialer::default()),
            Err(_) => {
                let message = "Could not initialize the browser network runtime.";
                emit_error(&self.on_event, message, false);
                emit_connection(&self.on_event, "disconnected");
                return rejected_promise(message);
            }
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
            let config = attachment_config(private_key);
            let (mut network, _oracle, attachments) =
                AttachmentNetwork::<_, _, WebSocketConnection, RejectInbound>::new(
                    context.clone(),
                    config,
                );
            let (sender, mut receiver) = network.register(
                CHAT_CHANNEL,
                Quota::per_second(NonZeroU32::new(32).expect("non-zero quota")),
                CHANNEL_BACKLOG,
            );
            let _network = network.start();

            let connection = match context.dial(&pairing.websocket_endpoint).await {
                Ok(connection) => connection,
                Err(_) => {
                    connection_failed(&state, generation, &on_event, result_sender);
                    return;
                }
            };
            if attachments
                .attach_outbound(pairing.desktop_public_key.clone(), connection)
                .await
                .is_err()
            {
                connection_failed(&state, generation, &on_event, result_sender);
                return;
            }

            if !is_current(&state, generation) {
                let _ = result_sender.send(Err("Connection was canceled."));
                return;
            }
            {
                let mut current = state.borrow_mut();
                current.sender = Some(sender);
                current.peer = Some(pairing.desktop_public_key.clone());
            }
            emit_peer(&on_event, &pairing.desktop_public_key.to_string());
            emit_connection(&on_event, "connected");
            let _ = result_sender.send(Ok(()));

            let mut next_message_id = 0_u64;
            loop {
                let Ok((sender, message)) = receiver.recv().await else {
                    break;
                };
                if sender != pairing.desktop_public_key {
                    emit_error(
                        &on_event,
                        "Ignored a message from an unexpected peer.",
                        false,
                    );
                    continue;
                }
                let bytes = message.as_ref();
                let Some((source, text)) = bytes.split_at_checked(32) else {
                    emit_error(&on_event, "Ignored a malformed chat message.", false);
                    continue;
                };
                if text.len() > MAX_CHAT_MESSAGE_SIZE {
                    emit_error(&on_event, "Ignored an oversized chat message.", false);
                    continue;
                }
                let Ok(source) = ed25519::PublicKey::decode(source) else {
                    emit_error(
                        &on_event,
                        "Ignored a chat message with an invalid identity.",
                        false,
                    );
                    continue;
                };
                let Ok(text) = std::str::from_utf8(text) else {
                    emit_error(
                        &on_event,
                        "Ignored a chat message that was not valid UTF-8.",
                        false,
                    );
                    continue;
                };
                next_message_id = next_message_id.wrapping_add(1);
                emit_message(
                    &on_event,
                    &format!("{generation}-{next_message_id}"),
                    &source.to_string(),
                    text,
                );
            }

            if clear_connection(&state, generation) {
                emit_error(
                    &on_event,
                    "The authenticated peer connection closed. Scan a fresh invite to rejoin.",
                    false,
                );
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
                .map_err(|message| JsValue::from_str(message))
        })
    }

    /// Stop the runtime and close the active transport.
    pub fn disconnect(&self) {
        self.stop(true);
    }
}

impl BrowserChat {
    fn stop(&self, emit: bool) {
        let stopped = self.state.borrow_mut().stop();
        if emit && stopped {
            emit_connection(&self.on_event, "disconnected");
        }
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

#[derive(Clone, Copy)]
struct RejectInbound;

impl PeerAdmission<ed25519::PublicKey, WebSocketOrigin> for RejectInbound {
    type Permit = ();

    fn pre_auth(&self, _info: &ConnectionInfo<WebSocketOrigin>) -> Result<Self::Permit, Rejected> {
        Err(Rejected)
    }

    async fn post_auth(
        &self,
        _permit: Self::Permit,
        _peer: &ed25519::PublicKey,
        _info: &ConnectionInfo<WebSocketOrigin>,
    ) -> Result<(), Rejected> {
        Err(Rejected)
    }
}

fn attachment_config(
    private_key: ed25519::PrivateKey,
) -> AttachmentConfig<ed25519::PrivateKey, RejectInbound> {
    AttachmentConfig {
        stream: encrypted::Config {
            signing_key: private_key,
            namespace: CHAT_NAMESPACE.to_vec(),
            max_message_size: MAX_NETWORK_MESSAGE_SIZE,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        },
        admission: RejectInbound,
        mailbox_size: NZUsize!(128),
        send_batch_size: NZUsize!(8),
        ping_frequency: Duration::from_secs(30),
        tracked_peer_sets: NZUsize!(1),
        peer_connection_cooldown: Duration::ZERO,
        block_duration: Duration::from_secs(60),
    }
}

fn validate_pairing(input: &str) -> Result<ValidatedPairing, &'static str> {
    if input.is_empty() || input.len() > MAX_PAIRING_PAYLOAD_SIZE {
        return Err("The pairing payload has an invalid size.");
    }
    let payload: PairingPayload = serde_json::from_str(input)
        .map_err(|_| "The pairing payload is not valid canonical JSON.")?;
    if payload.version != 1 {
        return Err("The pairing payload version is not supported.");
    }
    if payload.desktop_public_key.len() != 64
        || !payload
            .desktop_public_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("The pairing payload contains an invalid Ed25519 public key.");
    }
    let key_bytes = commonware_formatting::from_hex(&payload.desktop_public_key)
        .ok_or("The pairing payload contains an invalid Ed25519 public key.")?;
    let desktop_public_key = ed25519::PublicKey::decode(key_bytes.as_slice())
        .map_err(|_| "The pairing payload contains an invalid Ed25519 public key.")?;

    if !valid_base64url::<32>(&payload.capability, 43) {
        return Err("The pairing payload contains an invalid capability.");
    }
    if !valid_base64url::<16>(&payload.session_id, 22) {
        return Err("The pairing payload contains an invalid session identifier.");
    }
    let now = (Date::now() / 1_000.0).floor() as u64;
    if payload.expires_at <= now || payload.expires_at > 9_007_199_254_740_991 {
        return Err("The pairing session has expired or has an invalid expiry.");
    }
    if payload.websocket_url.len() > MAX_ENDPOINT_LEN {
        return Err("The pairing WebSocket endpoint is too long.");
    }

    let mut url = Url::parse(&payload.websocket_url)
        .map_err(|_| "The pairing payload contains an invalid WebSocket endpoint.")?;
    if !matches!(url.scheme(), "ws" | "wss")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err("The pairing payload contains an invalid WebSocket endpoint.");
    }
    url.query_pairs_mut()
        .append_pair("sid", &payload.session_id)
        .append_pair("cap", &payload.capability);
    let websocket_endpoint = WebSocketEndpoint::new(url.to_string())
        .map_err(|_| "The pairing payload contains an invalid WebSocket endpoint.")?;

    Ok(ValidatedPairing {
        desktop_public_key,
        websocket_endpoint,
    })
}

fn valid_base64url<const N: usize>(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && URL_SAFE_NO_PAD
            .decode(value)
            .ok()
            .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
            .is_some()
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

fn connection_failed(
    state: &RefCell<State>,
    generation: u64,
    on_event: &Function,
    result_sender: oneshot::Sender<Result<(), &'static str>>,
) {
    let message = "Could not establish an authenticated connection to the desktop.";
    if !clear_connection(state, generation) {
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

fn clear_connection(state: &RefCell<State>, generation: u64) -> bool {
    let mut current = state.borrow_mut();
    if current.generation != generation {
        return false;
    }
    current.sender = None;
    current.peer = None;
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
