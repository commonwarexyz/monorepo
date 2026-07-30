export type ConnectionState = "connecting" | "connected" | "reconnecting" | "disconnected";

export type ChatEvent =
  | { type: "connection"; state: ConnectionState; attempt?: number }
  | { type: "peer"; publicKey: string }
  | { type: "message"; id: string; sender: string; text: string; receivedAt: number }
  | { type: "error"; message: string; recoverable: boolean };

export interface SignalingPrimitive {
  seal(nonce: Uint8Array, additionalData: Uint8Array, plaintext: Uint8Array): Uint8Array;
  open(nonce: Uint8Array, additionalData: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}

export interface BrowserP2pSession {
  publicKey(): string;
  createSignalingCipher(session: Uint8Array, secret: Uint8Array): SignalingPrimitive;
  prepare(peerConnection: RTCPeerConnection, dataChannel: RTCDataChannel): void;
  attach(
    expectedPeer: string,
    outbound: boolean,
  ): Promise<void>;
  send(text: string): Promise<void>;
  disconnect(): void;
  free(): void;
}

interface BrowserP2pWasmModule {
  default?: (moduleOrPath?: unknown) => Promise<unknown>;
  createBrowserChat?: (onEvent: (event: ChatEvent) => void) => BrowserP2pSession;
}

export const WASM_MODULE_URL = "/wasm/browser_p2p.js";

export async function createBrowserChat(
  onEvent: (event: ChatEvent) => void,
): Promise<BrowserP2pSession> {
  let module: BrowserP2pWasmModule;

  try {
    module = (await import(WASM_MODULE_URL)) as BrowserP2pWasmModule;
  } catch (error) {
    throw bridgeError("Could not load the Commonware WASM module", error);
  }

  try {
    await module.default?.();
  } catch (error) {
    throw bridgeError("Could not initialize the Commonware WASM module", error);
  }

  if (typeof module.createBrowserChat !== "function") {
    throw new Error(
      "The Commonware WASM module does not export createBrowserChat. Build the Rust browser-p2p package before running this frontend.",
    );
  }

  const session = module.createBrowserChat(onEvent);
  validateSession(session);
  return session;
}

function validateSession(value: unknown): asserts value is BrowserP2pSession {
  if (typeof value !== "object" || value === null) {
    throw new Error("The Commonware WASM bridge returned an invalid chat session.");
  }

  const session = value as Partial<BrowserP2pSession>;
  const methods: Array<keyof BrowserP2pSession> = [
    "publicKey",
    "createSignalingCipher",
    "prepare",
    "attach",
    "send",
    "disconnect",
    "free",
  ];

  if (methods.some((method) => typeof session[method] !== "function")) {
    throw new Error("The Commonware WASM chat session does not match the expected bridge API.");
  }

  const validSession = session as BrowserP2pSession;
  const publicKey = validSession.publicKey();
  if (!/^[0-9a-f]{64}$/i.test(publicKey)) {
    validSession.free();
    throw new Error("The Commonware WASM bridge returned an invalid Ed25519 public key.");
  }
}

function bridgeError(message: string, cause: unknown): Error {
  const detail = cause instanceof Error ? cause.message : String(cause);
  return new Error(`${message}: ${detail}`);
}
