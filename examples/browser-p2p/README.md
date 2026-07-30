# Browser P2P chat

This example connects two ordinary browser tabs through an ordered, reliable WebRTC data channel.
Each page load creates a fresh Ed25519 identity in WASM. Commonware authenticates that identity,
encrypts the byte stream, and exposes chat through `authenticated::lookup` channels.

A small Bun rendezvous service serves the application and forwards WebRTC signaling. It never
receives Commonware or chat traffic. Signaling payloads are encrypted in the browsers with a key
derived from the one-time QR secret, so the rendezvous cannot read or replace the SDP, ICE
candidates, or responder key. The signaling WebSockets close after the Commonware handshake.

## Prerequisites

- Rust 1.95 or newer
- Bun 1.3 or newer
- `just`
- the `wasm32-unknown-unknown` Rust target
- `wasm-bindgen-cli` matching `browser/wasm/Cargo.lock` (currently 0.2.126)

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.126 --locked
```

## Run

From `examples/browser-p2p`:

```bash
just run
```

Open the printed URL on the laptop. By default, the server binds to all interfaces and selects the
first non-loopback IPv4 address for the printed URL and QR link. The laptop creates an expiring
session and displays one QR code. Scan it with the phone. The laptop is the fixed WebRTC offerer,
the phone is the answerer, and both browsers pin the exact Commonware key learned through the
protected pairing transcript.

Set `PUBLIC_URL` when the automatically selected interface is not reachable from the phone, or
when a reverse proxy exposes the application at another address:

```bash
PUBLIC_URL=https://192.168.1.42:3000/ just run
```

`PUBLIC_URL` controls the printed and QR URLs; `HOST` controls the listening interface and defaults
to `0.0.0.0`. A genuinely internet-facing URL still requires routing, firewall, and NAT or proxy
configuration outside this example.

`http://localhost` is suitable for two tabs on one machine. Mobile browsers require a secure
context. Create a locally trusted certificate for the laptop's LAN hostname or address, then run:

```bash
TLS_CERT_FILE=./cert.pem TLS_KEY_FILE=./key.pem PORT=3000 just run
```

Open the printed `https://` URL. The certificate must cover that address and be trusted by the
phone.

Useful commands:

```bash
just doctor  # Check required tools.
just check   # Run TypeScript, Bun, Rust, and WASM checks.
just build   # Build the frontend and package the WASM module.
just run     # Build and start the Bun static/rendezvous service.
just clean   # Remove generated example output.
```

## ICE configuration

The default configuration has no ICE servers and is intended for same-LAN testing. Inject STUN or
TURN configuration through `COMMONWARE_ICE_SERVERS`:

```bash
COMMONWARE_ICE_SERVERS='[{"urls":"stun:stun.example.net:3478"}]' just run
```

The Bun service returns this bounded configuration from `/config.json`. Do not hardcode production
TURN credentials in the application bundle. A TURN-selected connection relays WebRTC packets and
is not a direct network path, although Commonware still protects peer identity and chat contents.

## Layout

- `browser/src/server.ts` serves static assets and routes bounded, opaque signaling envelopes.
- `browser/src/webrtc.ts` owns rendezvous, encrypted signaling, SDP, ICE, and channel negotiation.
- `browser/wasm/` owns ephemeral keys, the web runtime, Commonware authentication, and lookup.
- `webrtc/` at the workspace root adapts an established `RTCDataChannel` to Commonware `Sink` and
  `Stream` semantics.

The QR fragment contains a version, a 256-bit session identifier, an independent 256-bit pairing
secret, the laptop public key, and a five-minute expiry. URL fragments are not sent in the initial
HTTP request. The phone key is sent only in an encrypted signaling envelope. The Commonware
handshake remains the authoritative proof that each browser controls its advertised private key.

## Security and lifecycle

The rendezvous can deny service, delay messages, or drop messages. It cannot decrypt signaling,
impersonate either accepted Commonware key, or read chat traffic. Session state is memory-only,
limited to two roles, bounded by message count and bytes, and deleted after disconnect or expiry.

Reloading either page creates a new private key and requires a new QR after the session expires.
Mobile browsers may suspend WebRTC and timers in the background; the example does not promise
continuous background connectivity. Every replacement data channel must run a fresh Commonware
handshake.
