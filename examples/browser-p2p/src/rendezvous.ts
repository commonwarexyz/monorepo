import type { Role } from "./signaling";

const MAX_FRAME_BYTES = 52 * 1024;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export type ServerEvent =
  | { type: "ready" }
  | { type: "peer" }
  | { type: "signal"; payload: string }
  | { type: "error"; message: string };

export class RendezvousClient {
  readonly #socket: WebSocket;
  readonly #listeners = new Set<(event: ServerEvent) => void>();
  #ready: Promise<void>;
  #resolveReady!: () => void;
  #rejectReady!: (error: Error) => void;
  #closed = false;

  constructor(
    url: string,
    session: string,
    role: Role,
    createSocket: (url: string) => WebSocket = (socketUrl) => new WebSocket(socketUrl),
  ) {
    if (!SESSION_PATTERN.test(session)) {
      throw new Error("The rendezvous session is invalid.");
    }

    this.#ready = new Promise((resolve, reject) => {
      this.#resolveReady = resolve;
      this.#rejectReady = reject;
    });
    this.#socket = createSocket(url);
    this.#socket.addEventListener("open", () => {
      this.#socket.send(JSON.stringify({ type: role === "initiator" ? "create" : "join", session }));
    });
    this.#socket.addEventListener("message", (event) => this.#receive(event.data));
    this.#socket.addEventListener("error", () => {
      this.#fail("The rendezvous connection failed.");
    });
    this.#socket.addEventListener("close", () => {
      this.#fail("The rendezvous connection closed.");
    });
  }

  ready(): Promise<void> {
    return this.#ready;
  }

  onEvent(listener: (event: ServerEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  send(payload: string): void {
    if (this.#closed || this.#socket.readyState !== WebSocket.OPEN) {
      throw new Error("The rendezvous connection is not open.");
    }
    if (new TextEncoder().encode(payload).byteLength > MAX_FRAME_BYTES) {
      throw new Error("The signaling envelope is too large.");
    }
    this.#socket.send(JSON.stringify({ type: "signal", payload }));
  }

  close(): void {
    this.#closed = true;
    this.#socket.close(1000, "signaling complete");
    this.#listeners.clear();
  }

  #receive(data: unknown): void {
    if (typeof data !== "string" || data.length > MAX_FRAME_BYTES * 2) {
      this.close();
      return;
    }

    let event: unknown;
    try {
      event = JSON.parse(data);
    } catch {
      this.close();
      return;
    }
    if (!isServerEvent(event)) {
      this.close();
      return;
    }

    if (event.type === "ready") {
      this.#resolveReady();
    } else if (event.type === "error") {
      this.#fail(event.message);
      return;
    }
    for (const listener of this.#listeners) {
      listener(event);
    }
  }

  #fail(message: string): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#rejectReady(new Error(message));
    const event = { type: "error", message } as const;
    for (const listener of this.#listeners) {
      listener(event);
    }
    this.#listeners.clear();
    if (this.#socket.readyState < WebSocket.CLOSING) {
      this.#socket.close(1000, "signaling failed");
    }
  }
}

export function rendezvousUrl(location: Location): string {
  const url = new URL("/rendezvous", location.origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

function isServerEvent(value: unknown): value is ServerEvent {
  if (!isRecord(value) || typeof value.type !== "string" || Object.keys(value).length > 2) {
    return false;
  }
  if (value.type === "ready" || value.type === "peer") {
    return Object.keys(value).length === 1;
  }
  if (value.type === "signal") {
    return typeof value.payload === "string" && value.payload.length <= MAX_FRAME_BYTES;
  }
  return value.type === "error" && typeof value.message === "string" && value.message.length <= 160;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
