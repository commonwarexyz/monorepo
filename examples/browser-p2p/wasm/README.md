# Browser P2P WASM bridge

This standalone crate implements the module contract in `../src/bridge.ts`. It generates a fresh
ephemeral Ed25519 identity for each `createBrowserChat` call and attaches an established, reliable
WebRTC data channel to Commonware authenticated lookup. Signaling, SDP, and ICE remain entirely in
the browser application; the bridge only handles authenticated peer traffic.

Install `wasm-bindgen-cli` with the same version used by this crate, then build and generate the
browser loader:

```bash
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen \
  --target web \
  --out-dir ../dist/wasm \
  --out-name browser_p2p \
  target/wasm32-unknown-unknown/release/commonware_browser_p2p.wasm
```

The Bun server must expose that output at `/wasm/browser_p2p.js` and
`/wasm/browser_p2p_bg.wasm`.

For a production deployment, serve the JavaScript as `text/javascript`, the binary as
`application/wasm`, and prevent stale caching of the loader when deploying a new binary.
