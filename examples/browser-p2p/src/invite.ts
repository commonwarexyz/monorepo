export interface Invite {
  version: 1;
  session: string;
  secret: string;
  initiatorKey: string;
  expiresAt: number;
}

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;
const MAX_FRAGMENT_LENGTH = 320;
const INVITE_LIFETIME_SECONDS = 5 * 60;

export function createInvite(initiatorKey: string): Invite {
  if (!PUBLIC_KEY_PATTERN.test(initiatorKey)) {
    throw new Error("The initiator identity is invalid.");
  }

  return {
    version: 1,
    session: randomToken(),
    secret: randomToken(),
    initiatorKey,
    expiresAt: Math.floor(Date.now() / 1_000) + INVITE_LIFETIME_SECONDS,
  };
}

export function inviteUrl(invite: Invite, location: URL): string {
  const url = new URL(location.origin + location.pathname);
  url.hash = new URLSearchParams({
    v: String(invite.version),
    s: invite.session,
    k: invite.secret,
    i: invite.initiatorKey,
    e: String(invite.expiresAt),
  }).toString();
  return url.toString();
}

export function parseInvite(location: URL): Invite | undefined {
  if (!location.hash) {
    return undefined;
  }
  if (location.hash.length > MAX_FRAGMENT_LENGTH) {
    throw new Error("The invite is too long.");
  }

  const fields = new URLSearchParams(location.hash.slice(1));
  if (fields.get("v") !== "1") {
    throw new Error("This invite version is not supported.");
  }

  const session = fields.get("s") ?? "";
  const secret = fields.get("k") ?? "";
  const initiatorKey = (fields.get("i") ?? "").toLowerCase();
  const expiresAt = Number(fields.get("e"));
  if (!TOKEN_PATTERN.test(session) || !TOKEN_PATTERN.test(secret)) {
    throw new Error("The invite contains an invalid pairing secret.");
  }
  if (!PUBLIC_KEY_PATTERN.test(initiatorKey)) {
    throw new Error("The invite contains an invalid initiator identity.");
  }
  const now = Math.floor(Date.now() / 1_000);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) {
    throw new Error("The invite has expired.");
  }
  if (expiresAt > now + INVITE_LIFETIME_SECONDS) {
    throw new Error("The invite expiry is invalid.");
  }
  if (fields.size !== 5) {
    throw new Error("The invite contains unsupported fields.");
  }

  return { version: 1, session, secret, initiatorKey, expiresAt };
}

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return toBase64Url(bytes);
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function fromBase64Url(value: string, expectedLength?: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url value.");
  }

  try {
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (expectedLength !== undefined && bytes.length !== expectedLength) {
      throw new Error("Unexpected decoded length.");
    }
    return bytes;
  } catch {
    throw new Error("Invalid base64url value.");
  }
}
