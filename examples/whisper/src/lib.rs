//! Send encrypted messages directly to another browser using the browser runtime of
//! `commonware-runtime` and `commonware-stream`.
//!
//! Two pages connect by passing each other one string. The first page creates an invite, and
//! the second answers it with a reply. Each string holds a flag that marks it as an invite or a
//! reply, the page's public key, and a description of how to reach the page, all hex encoded.
//!
//! The users pass the strings along however they like, such as in a chat or an email. No
//! server carries the strings or the messages.
//!
//! ```text
//!  Page A                                                Page B
//!    |                                                     |
//!    |-- invite: hex(flag, key A, description A) --------->|   passed by the users
//!    |<--------- reply: hex(flag, key B, description B) ---|   passed by the users
//!    |                                                     |
//!    |<=============== WebRTC data channel ===============>|
//!    |                                                     |
//!    |-- handshake as key A, expecting key B ------------->|   B admits only key A
//!    |<================ encrypted messages ===============>|
//! ```
//!
//! Once connected, the pages authenticate the keys named in the strings and encrypt every
//! message to them. The pages trust the strings, so whoever can replace both a page's key and
//! its description on the way can stand in for that page.

#![cfg(target_arch = "wasm32")]

use bytes::Bytes;
use commonware_codec::{Decode as _, Encode as _, RangeCfg};
use commonware_cryptography::{
    ChaCha20Poly1305, Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_formatting::{from_hex, hex};
use commonware_macros::select;
use commonware_math::algebra::Random as _;
use commonware_runtime::{
    Clock as _, Error as RuntimeError, Spawner as _, Supervisor as _,
    browser::{Config, Context, Runner},
};
use commonware_stream::{
    Upgrader as _,
    cups::{self, Cups},
    sake::{self, Sake},
    utils::Timeout,
};
use commonware_utils::{Widen, channel::mpsc};
use js_sys::{Function, futures::spawn_local};
use std::time::Duration;
use thiserror::Error;
use wasm_bindgen::prelude::{JsError, JsValue, wasm_bindgen};

/// Namespace both pages bind their session to.
const NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_WHISPER";

/// Largest message a page sends or accepts, in bytes.
const MAX_MESSAGE_SIZE: u32 = 4096;

/// Largest description of how to reach a page that an invite or a reply may carry, in bytes.
const MAX_DESCRIPTION_SIZE: usize = 16 * 1024;

/// Longest invite or reply a page decodes. It holds a flag, a public key, a description, and
/// their framing, with every byte written as two characters.
const MAX_SIGNAL_SIZE: usize = 2 * (MAX_DESCRIPTION_SIZE + 64);

/// How long the inviting page waits to connect once it has the reply.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the replying page waits for the inviting page to connect.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long the pages may take to authenticate each other once connected.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How far apart the clocks of the two pages may be. The devices people carry keep worse time
/// than servers do.
const CLOCK_SKEW: Duration = Duration::from_secs(60);

/// Number of requests from the page that may wait for the session to handle them.
const BACKLOG: usize = 16;

/// Why a session ended.
#[derive(Debug, Error)]
enum Error {
    #[error("the page ended the session")]
    Dropped,
    #[error("the connection failed: {0}")]
    Connection(#[from] RuntimeError),
    #[error("{0}")]
    Handshake(String),
    #[error("the connection closed")]
    Closed,
}

/// A request from the page.
enum Request {
    /// Create an invite.
    Invite,
    /// Handle an invite or a reply from the other page.
    Signal(String),
    /// Send a message to the other page.
    Send(String),
}

/// Reports a session's progress to the page.
#[derive(Clone)]
struct Listener(Function);

impl Listener {
    fn emit(&self, event: &str, detail: &str) {
        let _ = self.0.call2(&JsValue::NULL, &event.into(), &detail.into());
    }
}

/// Formats what a page tells the other: whether this answers an invite, who the page is, and
/// how to reach it.
fn signal(answer: bool, me: &PublicKey, description: String) -> String {
    hex(&(answer, me.clone(), Bytes::from(description)).encode())
}

/// Parses a string formatted by [signal] on another page.
fn parse(signal: &str) -> Option<(bool, PublicKey, String)> {
    if signal.len() > MAX_SIGNAL_SIZE {
        return None;
    }
    let limit = RangeCfg::from(..=MAX_DESCRIPTION_SIZE);
    let (answer, peer, description) =
        <(bool, PublicKey, Bytes)>::decode_cfg(from_hex(signal)?, &((), (), limit)).ok()?;
    let description = String::from_utf8(description.into()).ok()?;
    Some((answer, peer, description))
}

/// Connects to another page, then exchanges messages with it until either page leaves.
async fn session(
    mut context: Context,
    mut requests: mpsc::Receiver<Request>,
    listener: &Listener,
) -> Result<(), Error> {
    // Create an identity for this session and the handshake that proves it.
    let signer = PrivateKey::random(&mut context);
    let me = signer.public_key();
    listener.emit("identity", &me.to_string());
    let upgrader = Timeout::new(
        Cups::<_, ChaCha20Poly1305>::new(
            Sake {
                signer,
                synchrony_bound: CLOCK_SKEW,
                max_handshake_age: CLOCK_SKEW + HANDSHAKE_TIMEOUT,
                version: sake::Version::V1,
            },
            cups::Version::V1,
        ),
        HANDSHAKE_TIMEOUT,
    );

    // Connect as whichever side the user picks. An inviting page waits for the reply and dials
    // the key it names. A replying page waits for the inviting page and admits only the key in
    // the invite.
    let (peer, mut sender, mut receiver) = loop {
        match requests.recv().await.ok_or(Error::Dropped)? {
            Request::Invite => {
                let (offer, offering) = context.offer().await?;
                listener.emit("invite", &signal(false, &me, offer));
                let (peer, answer) = loop {
                    match requests.recv().await.ok_or(Error::Dropped)? {
                        Request::Signal(reply) => match parse(&reply) {
                            Some((true, peer, answer)) => break (peer, answer),
                            _ => listener.emit("error", "that is not a reply to an invite"),
                        },
                        _ => listener.emit("error", "waiting for the reply to the invite"),
                    }
                };
                let (sink, stream) = context
                    .timeout(CONNECT_TIMEOUT, offering.connect(answer))
                    .await??;
                let (sender, receiver) = upgrader
                    .dial(
                        context.child("dialer"),
                        NAMESPACE,
                        MAX_MESSAGE_SIZE,
                        peer.clone(),
                        stream,
                        sink,
                    )
                    .await
                    .map_err(|err| Error::Handshake(err.to_string()))?;
                break (peer, sender, receiver);
            }
            Request::Signal(invite) => {
                let Some((false, inviter, offer)) = parse(&invite) else {
                    listener.emit("error", "that is not an invite");
                    continue;
                };
                let Ok((answer, answering)) = context.answer(offer).await else {
                    listener.emit("error", "that invite cannot be answered");
                    continue;
                };
                listener.emit("reply", &signal(true, &me, answer));

                // The inviting page connects once its user passes it the reply.
                let (sink, stream) = context
                    .timeout(REPLY_TIMEOUT, answering.connect())
                    .await??;
                break upgrader
                    .listen(
                        context.child("listener"),
                        NAMESPACE,
                        MAX_MESSAGE_SIZE,
                        move |dialer| async move { dialer == inviter },
                        stream,
                        sink,
                    )
                    .await
                    .map_err(|err| Error::Handshake(err.to_string()))?;
            }
            Request::Send(_) => listener.emit("error", "not connected yet"),
        }
    };
    listener.emit("connected", &peer.to_string());

    // Receive in a task of its own. A receive that is dropped while it waits cannot be
    // resumed, so it must not share a select with requests from the page.
    let mut receiving = context.child("receiver").spawn({
        let listener = listener.clone();
        move |_| async move {
            while let Ok(message) = receiver.recv().await {
                let Ok(message) = String::from_utf8(message.coalesce().as_ref().to_vec()) else {
                    break;
                };
                listener.emit("message", &message);
            }
        }
    });

    // Send the page's messages until the session ends.
    loop {
        select! {
            _ = &mut receiving => return Err(Error::Closed),
            request = requests.recv() => match request.ok_or(Error::Dropped)? {
                Request::Send(message)
                    if message.len() > Widen::<usize>::widen(MAX_MESSAGE_SIZE) =>
                {
                    listener.emit("error", "that message is too long");
                }
                Request::Send(message) => sender
                    .send(message.into_bytes())
                    .await
                    .map_err(|_| Error::Closed)?,
                _ => listener.emit("error", "already connected"),
            },
        }
    }
}

/// A session with one other page.
///
/// The page drives the session with [Whisper::invite], [Whisper::signal], and
/// [Whisper::send], and follows it through the listener it passes to [Whisper::new].
#[wasm_bindgen]
pub struct Whisper {
    requests: mpsc::Sender<Request>,
}

#[wasm_bindgen]
impl Whisper {
    /// Start a session.
    ///
    /// `stun_servers` lists the URLs of the STUN servers that tell this page its public
    /// address. Without one, only pages on the same device or local network can connect.
    ///
    /// `listener` is called as `listener(event, detail)` with these events:
    ///
    /// | Event | Detail |
    /// |-------|--------|
    /// | `identity` | The public key of this page. |
    /// | `invite` | The invite to pass to the other page. |
    /// | `reply` | The reply to pass back to the inviting page. |
    /// | `connected` | The public key the other page proved. |
    /// | `message` | A message from the other page. |
    /// | `error` | Why a request was ignored. |
    /// | `closed` | Why the session ended. |
    #[wasm_bindgen(constructor)]
    pub fn new(stun_servers: Vec<String>, listener: Function) -> Self {
        let (requests, received) = mpsc::channel(BACKLOG);
        let runner = Runner::new(Config::new().with_stun_servers(stun_servers));
        let listener = Listener(listener);
        spawn_local(runner.start(move |context| async move {
            if let Err(err) = session(context, received, &listener).await {
                listener.emit("closed", &err.to_string());
            }
        }));
        Self { requests }
    }

    /// Create an invite for the other page.
    pub fn invite(&self) -> Result<(), JsError> {
        self.request(Request::Invite)
    }

    /// Handle the invite or the reply the other page created.
    pub fn signal(&self, signal: String) -> Result<(), JsError> {
        self.request(Request::Signal(signal))
    }

    /// Send a message to the other page.
    pub fn send(&self, message: String) -> Result<(), JsError> {
        self.request(Request::Send(message))
    }

    fn request(&self, request: Request) -> Result<(), JsError> {
        self.requests
            .try_send(request)
            .map_err(|_| JsError::new("the session is busy or over"))
    }
}
