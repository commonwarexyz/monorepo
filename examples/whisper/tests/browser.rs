//! Tests of sessions that share one page, run in a browser with `wasm-bindgen-test`.

#![cfg(target_arch = "wasm32")]

use bytes::Bytes;
use commonware_codec::{Decode as _, RangeCfg};
use commonware_cryptography::ed25519::PublicKey;
use commonware_formatting::from_hex;
use commonware_runtime::{
    Clock as _,
    browser::{Address, Runner},
};
use commonware_utils::channel::mpsc;
use commonware_whisper::Whisper;
use std::time::Duration;
use wasm_bindgen::{JsCast as _, closure::Closure};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// Longest contact a page decodes.
const MAX_CONTACT_SIZE: usize = 2 * (Address::MAX_SIZE + 64);

/// How a session that ended because the pages could not authenticate each other begins the
/// reason it reports.
const HANDSHAKE: &str = "the handshake failed";

/// Events a session reported to its page.
type Events = mpsc::UnboundedReceiver<(String, String)>;

/// A session and what it reported about itself.
struct Page {
    whisper: Whisper,
    events: Events,
    key: String,
    contact: String,
}

impl Page {
    /// Starts a session that contacts no STUN server, so it only reaches pages on this device.
    async fn start() -> Self {
        let (events, mut received) = mpsc::unbounded_channel();
        let listener = Closure::<dyn FnMut(String, String)>::new(move |event, detail| {
            let _ = events.send((event, detail));
        });
        let whisper = Whisper::new(Vec::new(), listener.into_js_value().unchecked_into());
        let key = expect(&mut received, "identity").await;
        let contact = expect(&mut received, "contact").await;
        Self {
            whisper,
            events: received,
            key,
            contact,
        }
    }

    /// Returns the detail of the next event. Panics unless that event is `event`.
    async fn expect(&mut self, event: &str) -> String {
        expect(&mut self.events, event).await
    }

    /// Returns the address this page's contact names.
    fn address(&self) -> Address {
        let limit = RangeCfg::from(..=self.contact.len());
        let (_, address) =
            <(PublicKey, Bytes)>::decode_cfg(from_hex(&self.contact).unwrap(), &((), limit))
                .unwrap();
        str::from_utf8(&address).unwrap().parse().unwrap()
    }
}

/// Returns the detail of the next event. Panics unless that event is `event`.
async fn expect(events: &mut Events, event: &str) -> String {
    let (reported, detail) = events
        .recv()
        .await
        .expect("session must report another event");
    assert_eq!(reported, event, "{detail}");
    detail
}

/// Starts two sessions. Returns the one that begins the handshake once they connect, then the
/// one that waits for it.
async fn pair() -> (Page, Page) {
    let (a, b) = (Page::start().await, Page::start().await);
    if a.address() < b.address() {
        (a, b)
    } else {
        (b, a)
    }
}

/// Returns `contact` naming `key` in place of its own key, which it begins with.
fn replace_key(contact: &str, key: &str) -> String {
    format!("{key}{}", &contact[key.len()..])
}

/// Returns `contact` followed by spaces, which a page ignores, up to `len` characters.
fn pad(contact: &str, len: usize) -> String {
    format!("{contact:<len$}")
}

#[wasm_bindgen_test]
async fn test_pages_exchange_messages() {
    let (mut a, mut b) = pair().await;

    // Nothing but the two contacts passes between the sessions before they connect.
    a.whisper.dial(b.contact.clone()).unwrap();
    b.whisper.dial(a.contact.clone()).unwrap();
    assert_eq!(a.expect("connected").await, b.key);
    assert_eq!(b.expect("connected").await, a.key);

    // Messages arrive in order in both directions.
    a.whisper.send("hello".into()).unwrap();
    a.whisper.send("there".into()).unwrap();
    assert_eq!(b.expect("message").await, "hello");
    assert_eq!(b.expect("message").await, "there");
    b.whisper.send("world".into()).unwrap();
    assert_eq!(a.expect("message").await, "world");

    // A message at the limit arrives. One over the limit is refused without ending the
    // session.
    a.whisper.send("x".repeat(4096)).unwrap();
    assert_eq!(b.expect("message").await.len(), 4096);
    a.whisper.send("x".repeat(4097)).unwrap();
    a.expect("error").await;
    a.whisper.send("still here".into()).unwrap();
    assert_eq!(b.expect("message").await, "still here");

    // A page that leaves ends the other page's session.
    let Page {
        whisper,
        events: mut b_events,
        ..
    } = b;
    drop(whisper);
    expect(&mut b_events, "closed").await;
    a.expect("closed").await;
}

#[wasm_bindgen_test]
async fn test_page_that_waits_dials_first() {
    let (mut first, mut second) = pair().await;

    // The page that waits for the handshake dials well before the page that begins it.
    second.whisper.dial(first.contact.clone()).unwrap();
    Runner::default()
        .start(|context| async move { context.sleep(Duration::from_millis(500)).await })
        .await;
    first.whisper.dial(second.contact.clone()).unwrap();
    assert_eq!(first.expect("connected").await, second.key);
    assert_eq!(second.expect("connected").await, first.key);
    first.whisper.send("hello".into()).unwrap();
    assert_eq!(second.expect("message").await, "hello");
}

#[wasm_bindgen_test]
async fn test_misplaced_strings_are_refused() {
    let (mut a, mut b) = pair().await;

    // Nothing can be sent before connecting, and only a contact can be dialed.
    b.whisper.send("early".into()).unwrap();
    b.expect("error").await;
    b.whisper.dial("not hex".into()).unwrap();
    b.expect("error").await;
    b.whisper.dial(a.key.clone()).unwrap();
    b.expect("error").await;

    // A page refuses its own contact, and its own address under another key.
    a.whisper.dial(a.contact.clone()).unwrap();
    a.expect("error").await;
    a.whisper.dial(replace_key(&a.contact, &b.key)).unwrap();
    a.expect("error").await;

    // A contact padded past the longest string a page decodes is refused, although the
    // padding would be ignored.
    b.whisper
        .dial(pad(&a.contact, MAX_CONTACT_SIZE + 1))
        .unwrap();
    b.expect("error").await;

    // A page that has dialed refuses every request until the other page dials.
    a.whisper.dial(b.contact.clone()).unwrap();
    a.whisper.send("early".into()).unwrap();
    a.expect("error").await;
    a.whisper.dial(b.contact.clone()).unwrap();
    a.expect("error").await;

    // The sessions still connect afterwards, one of them with a contact padded to that length.
    b.whisper.dial(pad(&a.contact, MAX_CONTACT_SIZE)).unwrap();
    a.expect("connected").await;
    b.expect("connected").await;
}

#[wasm_bindgen_test]
async fn test_page_that_leaves_while_dialing_ends_session() {
    let (a, b) = pair().await;

    // The page dials a contact whose page has not dialed, then leaves.
    a.whisper.dial(b.contact.clone()).unwrap();
    let Page {
        whisper,
        mut events,
        ..
    } = a;
    drop(whisper);
    expect(&mut events, "closed").await;
}

#[wasm_bindgen_test]
async fn test_replaced_key_fails_handshake() {
    let (mut first, mut second) = pair().await;
    let other = Page::start().await;

    // The page that begins the handshake dials a contact that names another page's key.
    first
        .whisper
        .dial(replace_key(&second.contact, &other.key))
        .unwrap();
    second.whisper.dial(first.contact.clone()).unwrap();

    // The pages connect, but the second cannot prove the key the first expects.
    assert!(first.expect("closed").await.starts_with(HANDSHAKE));
    assert!(second.expect("closed").await.starts_with(HANDSHAKE));
}

#[wasm_bindgen_test]
async fn test_replaced_key_is_not_admitted() {
    let (mut first, mut second) = pair().await;
    let other = Page::start().await;

    // The page that waits for the handshake dials a contact that names another page's key.
    first.whisper.dial(second.contact.clone()).unwrap();
    second
        .whisper
        .dial(replace_key(&first.contact, &other.key))
        .unwrap();

    // The pages connect, but the second admits only the key in the contact it dialed.
    assert!(first.expect("closed").await.starts_with(HANDSHAKE));
    assert!(second.expect("closed").await.starts_with(HANDSHAKE));
}
