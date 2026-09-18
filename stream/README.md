# commonware-stream

[![Crates.io](https://img.shields.io/crates/v/commonware-stream.svg)](https://crates.io/crates/commonware-stream)
[![Docs.rs](https://docs.rs/commonware-stream/badge.svg)](https://docs.rs/commonware-stream)

Exchange messages over arbitrary transport.

Commonware CUPS (Counter Unidirectional Packet Stream) protects ordered messages with
implicit counter nonces. `cups::Handshake` establishes these streams using Commonware SAKE
(Simple Authenticated Key Exchange). `Handshake`, `Sender`, and `Receiver` are the
generic interfaces for connection setup and message exchange.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.
