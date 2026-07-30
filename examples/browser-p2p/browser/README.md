# Commonware browser P2P chat frontend

A dependency-light Bun frontend for the Commonware authenticated lookup chat example. The page never generates, receives, or stores private key material: the WASM module owns a fresh ephemeral Ed25519 identity for the lifetime of the page and exposes only its public key.

## Develop and validate

Requires Bun 1.3 or newer.

```bash
bun install
bun run dev
```

The development server prints its local URL. Run all frontend checks with:

```bash
bun run check
```

This type-checks the TypeScript, runs the pairing parser tests, and creates a minified production build in `dist/`.

## WASM bridge contract

The frontend dynamically loads `/wasm/browser_p2p.js`. This path is intentionally unresolved at bundle time so the Rust package can be built and deployed separately. Until that module exists, the app displays a visible “WASM unavailable” state and keeps networking controls disabled. It does not simulate connections or messages.

The generated module must export:

```ts
export default function init(moduleOrPath?: unknown): Promise<unknown>;

export function createBrowserChat(
  onEvent: (event: ChatEvent) => void,
): BrowserP2pSession;
```

`BrowserP2pSession` must implement `publicKey()`, `connect(pairingPayload)`, `send(text)`, `disconnect()`, and `free()` as defined in `src/bridge.ts`. `createBrowserChat` must generate a new Ed25519 private key internally on every call, must never return or persist it, and must use Commonware authenticated lookup for all peer events and messages.

`connect` receives canonical JSON after frontend validation:

```json
{
  "version": 1,
  "desktop_public_key": "64-character lowercase Ed25519 public key hex",
  "websocket_url": "ws://192.168.1.42:8080/pair",
  "capability": "43-character base64url 256-bit capability",
  "session_id": "22-character base64url 128-bit session ID",
  "expires_at": 1893456000
}
```

The input field also accepts this JSON encoded as base64url, prefixed with `commonware-chat:`, or supplied in an invite URL's `pair` query/hash parameter.

Pairing endpoints may use `wss://` or plain `ws://`. Plain WebSockets support direct pairing with a desktop on the same LAN, such as `ws://192.168.1.42:8080/pair`. Transport encryption, asset integrity, and bootstrap authenticity are outside this MVP; authenticated lookup still identifies chat peers by their Ed25519 public keys.

## Package and embed

```bash
bun install --frozen-lockfile
bun run build
```

`dist/` is the complete static frontend embedding input. Embed every emitted file while preserving its relative path and serve `index.html` for the application route. Separately place the wasm-bindgen JavaScript loader and its referenced `.wasm` binary beneath the host's `/wasm/` URL namespace, with the loader available exactly at `/wasm/browser_p2p.js`.

The static host should serve JavaScript as `text/javascript`, WebAssembly as `application/wasm`, and HTML with `Cache-Control: no-cache`. Hashed Bun assets may be cached immutably. The app makes no use of local storage, IndexedDB, cookies, or service workers.
