export interface PairingPayload {
  version: 1;
  desktop_public_key: string;
  websocket_url: string;
  capability: string;
  session_id: string;
  expires_at: number;
}

const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/i;
const CAPABILITY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{22}$/;

export function parsePairingPayload(input: string): PairingPayload {
  const value = input.trim();
  if (!value) {
    throw new Error("Enter a pairing payload.");
  }

  const decoded = unwrapPayload(value);
  let candidate: unknown;

  try {
    candidate = JSON.parse(decoded);
  } catch {
    throw new Error("The pairing payload is not valid JSON or base64url-encoded JSON.");
  }

  return validatePayload(candidate);
}

export function serializePairingPayload(payload: PairingPayload): string {
  return JSON.stringify(payload);
}

function unwrapPayload(value: string): string {
  if (value.startsWith("{")) {
    return value;
  }

  if (value.startsWith("commonware-chat:")) {
    return decodeBase64Url(value.slice("commonware-chat:".length));
  }

  try {
    const url = new URL(value);
    const encoded = url.searchParams.get("pair") ?? url.hash.match(/(?:^#|[?&])pair=([^&]+)/)?.[1];
    if (!encoded) {
      throw new Error("Invite URL does not contain a pair parameter.");
    }
    return decodeBase64Url(decodeURIComponent(encoded));
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Invite URL")) {
      throw error;
    }
  }

  return decodeBase64Url(value);
}

function decodeBase64Url(value: string): string {
  try {
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("The encoded pairing payload is malformed.");
  }
}

function validatePayload(candidate: unknown): PairingPayload {
  if (!isRecord(candidate)) {
    throw new Error("The pairing payload must be an object.");
  }

  if (candidate.version !== 1) {
    throw new Error("This pairing payload version is not supported.");
  }

  if (
    typeof candidate.desktop_public_key !== "string" ||
    !PUBLIC_KEY_PATTERN.test(candidate.desktop_public_key)
  ) {
    throw new Error("The pairing payload contains an invalid Ed25519 public key.");
  }

  if (
    typeof candidate.capability !== "string" ||
    !CAPABILITY_PATTERN.test(candidate.capability)
  ) {
    throw new Error("The pairing payload contains an invalid 256-bit capability.");
  }

  if (typeof candidate.session_id !== "string" || !SESSION_PATTERN.test(candidate.session_id)) {
    throw new Error("The pairing payload contains an invalid session identifier.");
  }

  const now = Math.floor(Date.now() / 1_000);
  if (
    typeof candidate.expires_at !== "number" ||
    !Number.isSafeInteger(candidate.expires_at) ||
    candidate.expires_at <= now
  ) {
    throw new Error("The pairing session has expired.");
  }

  if (typeof candidate.websocket_url !== "string") {
    throw new Error("The pairing payload is missing its WebSocket endpoint.");
  }

  let websocketUrl: URL;
  try {
    websocketUrl = new URL(candidate.websocket_url);
  } catch {
    throw new Error("The pairing payload contains an invalid WebSocket endpoint.");
  }

  if (websocketUrl.protocol !== "ws:" && websocketUrl.protocol !== "wss:") {
    throw new Error("Pairing endpoints must use WebSockets.");
  }
  if (websocketUrl.username || websocketUrl.password || websocketUrl.hash) {
    throw new Error("The pairing WebSocket endpoint contains unsupported URL components.");
  }

  return {
    version: 1,
    desktop_public_key: candidate.desktop_public_key.toLowerCase(),
    websocket_url: websocketUrl.toString(),
    capability: candidate.capability,
    session_id: candidate.session_id,
    expires_at: candidate.expires_at,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
