# Browser P2P desktop service

This standalone crate runs the native half of the LAN chat example. It generates a fresh Ed25519
identity on every start, creates five-minute one-use pairing capabilities, serves the embedded
frontend, accepts WebSocket connections, authenticates browsers through Commonware lookup, and
relays UTF-8 chat messages on channel `0`. A fresh invite is printed after every successful join,
allowing multiple ephemeral browser identities into the room without reusing a capability.

## Build and run

Build the browser and WASM artifacts first. From `examples/browser-p2p/browser`:

```bash
bun install --frozen-lockfile
bun run build
```

The Bun bundle must be in `examples/browser-p2p/browser/dist`. The wasm-bindgen loader must be at
`examples/browser-p2p/browser/dist/wasm/browser_p2p.js`, with its referenced `.wasm` file beside it,
before compiling the service. The service build embeds the contents of `dist`.

Then run from `examples/browser-p2p/service`:

```bash
cargo run --release
```

The service discovers a LAN address and binds separate temporary HTTP and WebSocket ports on all
IPv4 interfaces. The current WebSocket acceptor only returns upgraded connections, so serving
ordinary HTTP on that listener is not cleanly possible. The QR therefore contains an HTTP invite
URL whose `pair` value includes the separate WebSocket endpoint.

If automatic LAN address discovery selects the wrong interface, provide the advertised address:

```bash
cargo run --release -- --host 192.168.1.42
```

Open the terminal QR on a phone, or open the printed asset URL and paste the printed pairing JSON
into the page. Pairing data is carried in the URL fragment and is therefore absent from the initial
HTTP request. The capability is intentionally printed only as part of that one-time invite and QR.
Press Ctrl-C to stop the service. Restarting invalidates the identity and every previous invite.

## Validate

From `examples/browser-p2p/service`:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The authenticated stream namespace is `_COMMONWARE_BROWSER_P2P_CHAT`, browser-to-service messages
are raw UTF-8, and the application message limit is 16 KiB. Relayed messages prefix that text with
the authenticated browser's 32-byte Ed25519 public key. The WebSocket URL receives pairing
credentials as `sid=<22-character-base64url>&cap=<43-character-base64url>` query parameters.
