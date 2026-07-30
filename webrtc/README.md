# commonware-webrtc

[![Crates.io](https://img.shields.io/crates/v/commonware-webrtc.svg)](https://crates.io/crates/commonware-webrtc)
[![Docs.rs](https://docs.rs/commonware-webrtc/badge.svg)](https://docs.rs/commonware-webrtc)

Carry reliable Commonware byte streams over established browser WebRTC data channels.

The crate adapts a reliable, ordered `RTCDataChannel` to the transport-neutral
`commonware-runtime` `Connection`, `Sink`, and `Stream` traits. It does not perform signaling,
SDP or ICE negotiation, peer discovery, authentication, or encryption. Applications establish the
browser connection first and then attach it to `commonware-p2p`, which authenticates and encrypts
the resulting byte stream.

See [`examples/browser-p2p`](../examples/browser-p2p) for a complete two-browser chat using a
short-lived rendezvous service for signaling and direct WebRTC for Commonware traffic.

## Status

This crate is at **ALPHA** stability. See the workspace
[README](https://github.com/commonwarexyz/monorepo#stability) for details.
