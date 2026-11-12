//! Send encrypted messages directly to another browser using the browser runtime of
//! `commonware-runtime` and `commonware-stream`.
//!
//! Every page has a contact: its public key and the address of an endpoint it has bound, hex
//! encoded. Two pages connect once each dials the contact of the other. The users pass the
//! contacts along in either order and however they like, such as in a chat or an email. No
//! server carries the contacts or the messages.
//!
//! ```text
//!  Page A                                                Page B
//!    |                                                     |
//!    |-- contact A: hex(key A, address A) ---------------->|   passed by the users
//!    |<---------------- contact B: hex(key B, address B) --|   passed by the users
//!    |                                                     |
//!    |-- dial address B -------><-------- dial address A --|
//!    |<=============== WebRTC data channel ===============>|
//!    |                                                     |
//!    |<========== handshake between key A and key B ======>|   each expects the other's key
//!    |<================ encrypted messages ===============>|
//! ```
//!
//! Once connected, the pages authenticate the keys named in the contacts and encrypt every
//! message to them. The page with the smaller address begins that handshake. The pages trust
//! the contacts, so whoever can replace a page's contact on the way can stand in for that page.

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
    Clock as _, Spawner as _, Supervisor as _,
    browser::{Address, Config, Context, Runner},
};
use commonware_stream::{
    Upgrader as _,
    cups::{self, Cups},
    sake::{self, Sake},
    utils::Timeout,
};
use commonware_utils::{Widen, channel::mpsc};
use js_sys::{Function, futures::spawn_local};
use std::{pin::pin, time::Duration};
use thiserror::Error;
use wasm_bindgen::prelude::{JsError, JsValue, wasm_bindgen};

/// Namespace both pages bind their session to.
const NAMESPACE: &[u8] = b"_COMMONWARE_EXAMPLES_WHISPER";

/// Largest message a page sends or accepts, in bytes.
const MAX_MESSAGE_SIZE: u32 = 4096;

/// Longest contact a page decodes. It holds a public key, an address, and their framing, with
/// every byte written as two characters.
const MAX_CONTACT_SIZE: usize = 2 * (Address::MAX_SIZE + 64);

/// How long a page may take to learn where it can be reached.
const BIND_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a page that has dialed waits for the other page to dial it.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

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
    #[error("this page could not learn where it can be reached")]
    Unbound,
    #[error("the pages could not reach each other")]
    Unreachable,
    #[error("the handshake failed: {0}")]
    Handshake(String),
    #[error("the connection closed")]
    Closed,
}

/// A request from the page.
enum Request {
    /// Dial the contact of the other page.
    Dial(String),
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

/// Formats what a page tells the other: who it is and where to dial it.
fn contact(me: &PublicKey, address: &Address) -> String {
    hex(&(me.clone(), Bytes::from(address.to_string())).encode())
}

/// Parses a string formatted by [contact] on another page.
fn parse(contact: &str) -> Option<(PublicKey, Address)> {
    if contact.len() > MAX_CONTACT_SIZE {
        return None;
    }
    let limit = RangeCfg::from(..=Address::MAX_SIZE);
    let (peer, address) =
        <(PublicKey, Bytes)>::decode_cfg(from_hex(contact)?, &((), limit)).ok()?;
    let address = str::from_utf8(&address).ok()?.parse().ok()?;
    Some((peer, address))
}

/// Dials another page, then exchanges messages with it until either page leaves.
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

    // Bind the endpoint the other page dials, and tell the page how to reach it.
    let Ok(Ok(endpoint)) = context.timeout(BIND_TIMEOUT, context.bind()).await else {
        return Err(Error::Unbound);
    };
    listener.emit("contact", &contact(&me, endpoint.address()));

    // Wait for the contact of the other page.
    let (peer, address) = loop {
        match requests.recv().await.ok_or(Error::Dropped)? {
            Request::Dial(dialed) => match parse(&dialed) {
                Some((_, address)) if address == *endpoint.address() => {
                    listener.emit("error", "that is the contact of this page");
                }
                Some(dialed) => break dialed,
                None => listener.emit("error", "that is not a contact"),
            },
            Request::Send(_) => listener.emit("error", "not connected yet"),
        }
    };

    // Dial the other page, which dials this one. The page can ask for nothing else until
    // they connect.
    let begins = *endpoint.address() < address;
    let (sink, stream) = {
        let mut dial = pin!(context.timeout(DIAL_TIMEOUT, endpoint.dial(address)));
        loop {
            select! {
                dialed = &mut dial => match dialed {
                    Ok(Ok(connection)) => break connection,
                    _ => return Err(Error::Unreachable),
                },
                request = requests.recv() => match request.ok_or(Error::Dropped)? {
                    Request::Dial(_) => listener.emit("error", "already dialing"),
                    Request::Send(_) => listener.emit("error", "not connected yet"),
                },
            }
        }
    };

    // Both pages dialed, so their addresses decide which one begins the handshake. That page
    // expects the key in the contact it dialed, and the other page admits only the key in the
    // contact it dialed.
    let (mut sender, mut receiver) = if begins {
        upgrader
            .dial(
                context.child("dialer"),
                NAMESPACE,
                MAX_MESSAGE_SIZE,
                peer.clone(),
                stream,
                sink,
            )
            .await
            .map_err(|err| Error::Handshake(err.to_string()))?
    } else {
        let expected = peer.clone();
        let (_, sender, receiver) = upgrader
            .listen(
                context.child("listener"),
                NAMESPACE,
                MAX_MESSAGE_SIZE,
                move |dialer| async move { dialer == expected },
                stream,
                sink,
            )
            .await
            .map_err(|err| Error::Handshake(err.to_string()))?;
        (sender, receiver)
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
/// The page drives the session with [Whisper::dial] and [Whisper::send], and follows it through
/// the listener it passes to [Whisper::new].
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
    /// | `contact` | The contact of this page, to pass to the other page. |
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

    /// Dial the contact the other page passed. That page must dial this page's contact too.
    pub fn dial(&self, contact: String) -> Result<(), JsError> {
        self.request(Request::Dial(contact))
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
