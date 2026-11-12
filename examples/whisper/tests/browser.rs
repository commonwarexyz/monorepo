//! Tests of sessions that share one page, run in a browser with `wasm-bindgen-test`.

#![cfg(target_arch = "wasm32")]

use commonware_utils::channel::mpsc;
use commonware_whisper::Whisper;
use wasm_bindgen::{JsCast as _, closure::Closure};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// Events a session reported to its page.
type Events = mpsc::UnboundedReceiver<(String, String)>;

/// Starts a session that contacts no STUN server, so it only reaches pages on this device.
fn start() -> (Whisper, Events) {
    let (events, received) = mpsc::unbounded_channel();
    let listener = Closure::<dyn FnMut(String, String)>::new(move |event, detail| {
        let _ = events.send((event, detail));
    });
    let whisper = Whisper::new(Vec::new(), listener.into_js_value().unchecked_into());
    (whisper, received)
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

/// Returns `signal` naming `key` in place of its own key. The key follows the one-byte flag
/// that marks a reply.
fn replace_key(signal: &str, key: &str) -> String {
    format!("{}{}{}", &signal[..2], key, &signal[2 + key.len()..])
}

#[wasm_bindgen_test]
async fn test_pages_exchange_messages() {
    let (a, mut a_events) = start();
    let (b, mut b_events) = start();
    let a_key = expect(&mut a_events, "identity").await;
    let b_key = expect(&mut b_events, "identity").await;

    // Nothing but the two strings passes between the sessions before they connect.
    a.invite().unwrap();
    let invite = expect(&mut a_events, "invite").await;
    b.signal(invite).unwrap();
    let reply = expect(&mut b_events, "reply").await;
    a.signal(reply).unwrap();
    assert_eq!(expect(&mut a_events, "connected").await, b_key);
    assert_eq!(expect(&mut b_events, "connected").await, a_key);

    // Messages arrive in order in both directions.
    a.send("hello".into()).unwrap();
    a.send("there".into()).unwrap();
    assert_eq!(expect(&mut b_events, "message").await, "hello");
    assert_eq!(expect(&mut b_events, "message").await, "there");
    b.send("world".into()).unwrap();
    assert_eq!(expect(&mut a_events, "message").await, "world");

    // A message at the limit arrives. One over the limit is refused without ending the
    // session.
    a.send("x".repeat(4096)).unwrap();
    assert_eq!(expect(&mut b_events, "message").await.len(), 4096);
    a.send("x".repeat(4097)).unwrap();
    expect(&mut a_events, "error").await;
    a.send("still here".into()).unwrap();
    assert_eq!(expect(&mut b_events, "message").await, "still here");

    // A page that leaves ends the other page's session.
    drop(b);
    expect(&mut b_events, "closed").await;
    expect(&mut a_events, "closed").await;
}

#[wasm_bindgen_test]
async fn test_misplaced_strings_are_refused() {
    let (a, mut a_events) = start();
    let (b, mut b_events) = start();
    let (c, mut c_events) = start();
    expect(&mut a_events, "identity").await;
    expect(&mut b_events, "identity").await;
    expect(&mut c_events, "identity").await;

    // Nothing can be sent before connecting, and only an invite can be answered.
    b.send("early".into()).unwrap();
    expect(&mut b_events, "error").await;
    b.signal("not hex".into()).unwrap();
    expect(&mut b_events, "error").await;

    // A page waiting for a reply refuses an invite.
    a.invite().unwrap();
    let invite = expect(&mut a_events, "invite").await;
    a.signal(invite.clone()).unwrap();
    expect(&mut a_events, "error").await;

    // An invite padded past the longest string a page decodes is refused, although the
    // padding would be ignored.
    b.signal(format!("{invite}{}", " ".repeat(32_896))).unwrap();
    expect(&mut b_events, "error").await;

    // The sessions still connect afterwards, and a page that created no invite refuses the
    // reply.
    b.signal(invite).unwrap();
    let reply = expect(&mut b_events, "reply").await;
    c.signal(reply.clone()).unwrap();
    expect(&mut c_events, "error").await;
    a.signal(reply).unwrap();
    expect(&mut a_events, "connected").await;
    expect(&mut b_events, "connected").await;
}

#[wasm_bindgen_test]
async fn test_replaced_reply_key_fails_handshake() {
    let (a, mut a_events) = start();
    let (b, mut b_events) = start();
    let (_c, mut c_events) = start();
    expect(&mut a_events, "identity").await;
    expect(&mut b_events, "identity").await;
    let c_key = expect(&mut c_events, "identity").await;

    // The reply reaches the inviting page naming another page's key.
    a.invite().unwrap();
    let invite = expect(&mut a_events, "invite").await;
    b.signal(invite).unwrap();
    let reply = expect(&mut b_events, "reply").await;
    a.signal(replace_key(&reply, &c_key)).unwrap();

    // The pages connect, but the replying page cannot prove the key the reply named.
    expect(&mut a_events, "closed").await;
    expect(&mut b_events, "closed").await;
}

#[wasm_bindgen_test]
async fn test_replaced_invite_key_is_not_admitted() {
    let (a, mut a_events) = start();
    let (b, mut b_events) = start();
    let (_c, mut c_events) = start();
    expect(&mut a_events, "identity").await;
    expect(&mut b_events, "identity").await;
    let c_key = expect(&mut c_events, "identity").await;

    // The invite reaches the replying page naming another page's key.
    a.invite().unwrap();
    let invite = expect(&mut a_events, "invite").await;
    b.signal(replace_key(&invite, &c_key)).unwrap();
    let reply = expect(&mut b_events, "reply").await;
    a.signal(reply).unwrap();

    // The pages connect, but the replying page admits only the key the invite named.
    expect(&mut a_events, "closed").await;
    expect(&mut b_events, "closed").await;
}
