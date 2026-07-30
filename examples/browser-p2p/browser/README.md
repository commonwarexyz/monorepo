# Browser package

This Bun package contains the static chat interface and the signaling-only rendezvous service for
the browser P2P example. See the parent [README](../README.md) for setup, architecture, and security
details.

The browser without an invite creates a five-minute pairing session and displays one QR code. The
scanning browser answers through encrypted WebRTC signaling. After Commonware authenticates both
ephemeral Ed25519 keys over the direct data channel, both signaling WebSockets close.

```bash
bun install --frozen-lockfile
bun run lint
bun test
bun run build
bun run serve
```

`dist/` contains the hashed frontend assets. The parent build packages wasm-bindgen output beneath
`dist/wasm`. `COMMONWARE_ICE_SERVERS` supplies an optional JSON array of ICE servers. Set
`TLS_CERT_FILE` and `TLS_KEY_FILE` together when serving a mobile browser, which requires a trusted
secure context for WebCrypto and WebRTC. The server advertises a non-loopback LAN address by
default. Set `PUBLIC_URL` to override the URL placed in invites, and `HOST` to override the listening
interface.

Private keys remain inside the Rust WASM module and are regenerated on each page load. The Bun
service handles only static files, bounded room state, opaque signaling envelopes, and ICE server
configuration. It never receives Commonware frames or chat messages.
