# Browser P2P chat

This example runs a small authenticated chat room between mobile or desktop browsers on the same
LAN. Each page load creates a fresh Ed25519 identity inside WASM. Browsers connect outbound over a
binary WebSocket, Commonware authenticates and encrypts that byte stream, and
`authenticated::lookup` carries chat messages through its normal sender and receiver channels.

The desktop process serves the browser bundle, accepts WebSocket upgrades, and relays messages
between authenticated browser keys. It prints a new one-time invite after each browser joins, so
every participant uses a distinct capability. A capability is reserved during the upgrade and is
consumed only after the Commonware handshake authenticates the browser key.

## Run it

Install Rust 1.95 or newer, [Bun](https://bun.sh/) 1.3 or newer, `just`, the WASM target, and the
`wasm-bindgen` CLI version recorded in `browser/wasm/Cargo.lock` (currently `0.2.126`):

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.126 --locked
```

Then, from this directory:

```bash
just run
```

`just run` installs the locked Bun dependencies, checks and bundles the frontend, builds the Rust
WASM bridge, embeds the resulting assets in the desktop binary, and starts the LAN service. If the
wrong network interface is detected, pass the LAN address directly:

```bash
just build
cargo run --locked --release --manifest-path service/Cargo.toml -- --host 192.168.1.42
```

Scan the printed QR code with the first browser. After that browser authenticates, the service
prints the next one-time QR for another participant. Messages are relayed only to the other browser
keys currently known to the room; the relay includes the authenticated source key in the chat
frame, so recipients can identify the ephemeral sender.

Useful commands:

```bash
just doctor   # Check required local tools.
just check    # Run Bun checks, the WASM check, service tests, and service clippy.
just build    # Produce the embedded release service without running it.
just clean    # Remove generated example build output.
```

## Layout

- `browser/` is the minimal Bun/TypeScript interface and styling.
- `browser/wasm/` owns the ephemeral key, web runtime, WebSocket dial, encrypted handshake, and
  authenticated lookup actors.
- `service/` owns static asset delivery, one-time pairing sessions, native WebSocket acceptance,
  inbound peer admission, and the chat relay.

The Bun build is intentionally dependency-light and emits hashed production assets. The
`wasm-bindgen` loader and binary are packaged under `browser/dist/wasm`, then the service build
embeds all of `browser/dist`.

## Pairing and security boundary

The invite is versioned and contains the asset URL, a direct `ws://` LAN endpoint, a 256-bit
one-time capability, a 128-bit session ID, a short expiry, and the desktop Commonware public key.
The capability-bearing payload is placed in the HTTP URL fragment, so browsers do not send it in
the initial asset request. The WASM bridge later adds the bounded session and capability values to
the WebSocket upgrade request.

The browser pins the desktop key from the invite. The desktop learns each browser's fresh key only
from the Commonware encrypted handshake; neither the WebSocket upgrade nor the pairing capability
is treated as peer identity. Chat payloads are binary WebSocket messages carrying Commonware's
encrypted stream protocol, not plaintext WebSocket chat frames.

The initial asset page is delivered over plain LAN HTTP. Commonware authenticates and encrypts the
connection only after that code runs; it cannot authenticate HTML, JavaScript, or WASM that an
active network attacker modified beforehand. A hardened deployment should use an installed PWA,
a native wrapper, locally trusted TLS, or another authenticated bootstrap channel.

Closing or reloading a page discards its private key. The current example requires a fresh invite
after that identity is lost and does not promise uninterrupted background connectivity on mobile
browsers.
