import { fromBase64Url, toBase64Url } from "./invite";

export type Role = "initiator" | "responder";

export type Signal =
  | { type: "identity"; publicKey: string }
  | { type: "description"; description: RTCSessionDescriptionInit }
  | { type: "candidate"; candidate: RTCIceCandidateInit }
  | { type: "adapter-ready" };

interface Envelope {
  v: 1;
  s: string;
  from: Role;
  seq: number;
  iv: string;
  body: string;
}

const INFO = new TextEncoder().encode("commonware-browser-p2p-signaling-v1");
const MAX_ENVELOPE_LENGTH = 48 * 1024;
const MAX_PLAINTEXT_LENGTH = 40 * 1024;
const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;

export class SignalingCipher {
  readonly #session: string;
  readonly #localRole: Role;
  readonly #remoteRole: Role;
  readonly #key: Promise<CryptoKey>;
  #sendSequence = 0;
  #receiveSequence = 0;

  constructor(session: string, secret: string, localRole: Role) {
    this.#session = session;
    this.#localRole = localRole;
    this.#remoteRole = localRole === "initiator" ? "responder" : "initiator";
    this.#key = deriveKey(session, secret);
  }

  async seal(signal: Signal): Promise<string> {
    validateSignal(signal);
    const plaintext = new TextEncoder().encode(JSON.stringify(signal));
    if (plaintext.byteLength > MAX_PLAINTEXT_LENGTH) {
      throw new Error("The signaling message is too large.");
    }

    const seq = this.#sendSequence;
    this.#sendSequence += 1;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: asArrayBuffer(iv),
        additionalData: asArrayBuffer(aad(this.#session, this.#localRole, seq)),
      },
      await this.#key,
      plaintext,
    );
    return JSON.stringify({
      v: 1,
      s: this.#session,
      from: this.#localRole,
      seq,
      iv: toBase64Url(iv),
      body: toBase64Url(new Uint8Array(ciphertext)),
    } satisfies Envelope);
  }

  async open(encoded: string): Promise<Signal> {
    if (encoded.length > MAX_ENVELOPE_LENGTH) {
      throw new Error("The signaling envelope is too large.");
    }

    const envelope = parseEnvelope(encoded);
    if (
      envelope.s !== this.#session ||
      envelope.from !== this.#remoteRole ||
      envelope.seq !== this.#receiveSequence
    ) {
      throw new Error("The signaling envelope is out of sequence.");
    }

    let plaintext: ArrayBuffer;
    try {
      plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: asArrayBuffer(fromBase64Url(envelope.iv, 12)),
          additionalData: asArrayBuffer(aad(envelope.s, envelope.from, envelope.seq)),
        },
        await this.#key,
        asArrayBuffer(fromBase64Url(envelope.body)),
      );
    } catch {
      throw new Error("The signaling envelope could not be authenticated.");
    }
    if (plaintext.byteLength > MAX_PLAINTEXT_LENGTH) {
      throw new Error("The signaling message is too large.");
    }

    let signal: unknown;
    try {
      signal = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
    } catch {
      throw new Error("The signaling message is malformed.");
    }
    validateSignal(signal);
    this.#receiveSequence += 1;
    return signal;
  }
}

async function deriveKey(session: string, secret: string): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(fromBase64Url(secret, 32)),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asArrayBuffer(fromBase64Url(session, 32)),
      info: asArrayBuffer(INFO),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function aad(session: string, role: Role, sequence: number): Uint8Array {
  return new TextEncoder().encode(`commonware-browser-p2p-v1\n${session}\n${role}\n${sequence}`);
}

function parseEnvelope(encoded: string): Envelope {
  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw new Error("The signaling envelope is malformed.");
  }
  if (!isRecord(value) || Object.keys(value).length !== 6) {
    throw new Error("The signaling envelope is malformed.");
  }
  if (
    value.v !== 1 ||
    typeof value.s !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.s) ||
    (value.from !== "initiator" && value.from !== "responder") ||
    typeof value.seq !== "number" ||
    !Number.isSafeInteger(value.seq) ||
    value.seq < 0 ||
    typeof value.iv !== "string" ||
    typeof value.body !== "string"
  ) {
    throw new Error("The signaling envelope is malformed.");
  }
  return value as unknown as Envelope;
}

function validateSignal(value: unknown): asserts value is Signal {
  if (!isRecord(value) || typeof value.type !== "string") {
    throw new Error("The signaling message is invalid.");
  }

  if (value.type === "identity") {
    if (Object.keys(value).length !== 2 || typeof value.publicKey !== "string" || !PUBLIC_KEY_PATTERN.test(value.publicKey)) {
      throw new Error("The signaling identity is invalid.");
    }
    return;
  }

  if (value.type === "description") {
    if (!isRecord(value.description) || Object.keys(value).length !== 2) {
      throw new Error("The session description is invalid.");
    }
    const { type, sdp } = value.description;
    if ((type !== "offer" && type !== "answer") || typeof sdp !== "string" || sdp.length > 32 * 1024) {
      throw new Error("The session description is invalid.");
    }
    return;
  }

  if (value.type === "candidate") {
    if (!isRecord(value.candidate) || typeof value.candidate.candidate !== "string" || value.candidate.candidate.length > 4096) {
      throw new Error("The ICE candidate is invalid.");
    }
    return;
  }

  if (value.type === "adapter-ready" && Object.keys(value).length === 1) {
    return;
  }

  throw new Error("The signaling message type is invalid.");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}
