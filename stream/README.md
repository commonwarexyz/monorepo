# commonware-stream

[![Crates.io](https://img.shields.io/crates/v/commonware-stream.svg)](https://crates.io/crates/commonware-stream)
[![Docs.rs](https://docs.rs/commonware-stream/badge.svg)](https://docs.rs/commonware-stream)

Exchange messages over arbitrary transport.

## Pluggable handshakes

`commonware_stream::Handshake` authenticates a connection and returns message streams. P2p
configurations take a handshake directly; use `encrypted::Handshake::new(signing_key)` for
the built-in encrypted stream. Direct trait callers own the handshake deadline and cancel
an attempt by dropping its future.

When migrating an `encrypted::Config`, move `signing_key`, `synchrony_bound`, and
`max_handshake_age` into its `handshake: encrypted::Handshake<_>` field. The namespace,
message limit, and handshake timeout remain on `Config`, and `time_information` is now
available on `config.handshake`. The free `encrypted::dial` and `encrypted::listen`
functions still enforce the configured timeout. Listener bouncers and their futures must
be `Send`; captured shared state can use thread-safe ownership such as `Arc`.

Handshake implementations borrow their namespace as `&[u8]`. Callers must choose a
message limit within the handshake's `MAX_SIZE`. The bouncer may see a claimed identity
before authentication completes; successful completion authenticates the returned identity.
