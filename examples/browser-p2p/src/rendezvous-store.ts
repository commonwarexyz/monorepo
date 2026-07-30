export interface RendezvousPeer {
  send(message: string): void;
  close(code: number, reason: string): void;
}

interface Room {
  initiator: RendezvousPeer;
  responder?: RendezvousPeer;
  expiresAt: number;
  messages: number;
  bytes: number;
}

export interface RendezvousLimits {
  roomLifetimeMs: number;
  replayLifetimeMs: number;
  maxMessages: number;
  maxBytes: number;
  maxMessageBytes: number;
  maxRooms: number;
}

export const DEFAULT_LIMITS: RendezvousLimits = {
  roomLifetimeMs: 5 * 60_000,
  replayLifetimeMs: 10 * 60_000,
  maxMessages: 256,
  maxBytes: 512 * 1024,
  maxMessageBytes: 52 * 1024,
  maxRooms: 10_000,
};

const SESSION_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export class RendezvousStore {
  readonly #rooms = new Map<string, Room>();
  readonly #used = new Map<string, number>();
  readonly #limits: RendezvousLimits;
  readonly #now: () => number;

  constructor(limits: RendezvousLimits = DEFAULT_LIMITS, now: () => number = Date.now) {
    this.#limits = limits;
    this.#now = now;
  }

  create(session: string, peer: RendezvousPeer): boolean {
    this.cleanup();
    if (!SESSION_PATTERN.test(session) || this.#rooms.size >= this.#limits.maxRooms) {
      reject(peer, "Session creation rejected.");
      return false;
    }
    if (this.#rooms.has(session) || this.#used.has(session)) {
      reject(peer, "Session is unavailable.");
      return false;
    }

    this.#rooms.set(session, {
      initiator: peer,
      expiresAt: this.#now() + this.#limits.roomLifetimeMs,
      messages: 0,
      bytes: 0,
    });
    peer.send(JSON.stringify({ type: "ready" }));
    return true;
  }

  join(session: string, peer: RendezvousPeer): boolean {
    this.cleanup();
    const room = this.#rooms.get(session);
    if (!SESSION_PATTERN.test(session) || !room || room.responder) {
      reject(peer, "Session is unavailable.");
      return false;
    }

    room.responder = peer;
    this.#used.set(session, this.#now() + this.#limits.replayLifetimeMs);
    peer.send(JSON.stringify({ type: "ready" }));
    room.initiator.send(JSON.stringify({ type: "peer" }));
    return true;
  }

  relay(session: string, sender: RendezvousPeer, payload: string): boolean {
    const room = this.#rooms.get(session);
    if (!room || typeof payload !== "string") {
      reject(sender, "Session is unavailable.");
      return false;
    }

    const senderIsInitiator = sender === room.initiator;
    const senderIsResponder = sender === room.responder;
    const recipient = senderIsInitiator ? room.responder : senderIsResponder ? room.initiator : undefined;
    const bytes = new TextEncoder().encode(payload).byteLength;
    if (
      !recipient ||
      bytes > this.#limits.maxMessageBytes ||
      room.messages >= this.#limits.maxMessages ||
      room.bytes + bytes > this.#limits.maxBytes
    ) {
      this.#destroy(session, 1008, "Signaling limit exceeded.");
      return false;
    }

    room.messages += 1;
    room.bytes += bytes;
    recipient.send(JSON.stringify({ type: "signal", payload }));
    return true;
  }

  disconnect(peer: RendezvousPeer): void {
    for (const [session, room] of this.#rooms) {
      if (room.initiator === peer || room.responder === peer) {
        this.#destroy(session, 1001, "Peer disconnected.");
        return;
      }
    }
  }

  cleanup(): void {
    const now = this.#now();
    for (const [session, room] of this.#rooms) {
      if (room.expiresAt <= now) {
        this.#destroy(session, 1008, "Session expired.");
      }
    }
    for (const [session, expiresAt] of this.#used) {
      if (expiresAt <= now) {
        this.#used.delete(session);
      }
    }
  }

  get size(): number {
    return this.#rooms.size;
  }

  #destroy(session: string, code: number, reason: string): void {
    const room = this.#rooms.get(session);
    if (!room) {
      return;
    }
    this.#rooms.delete(session);
    this.#used.set(session, this.#now() + this.#limits.replayLifetimeMs);
    room.initiator.close(code, reason);
    room.responder?.close(code, reason);
  }
}

function reject(peer: RendezvousPeer, message: string): void {
  peer.send(JSON.stringify({ type: "error", message }));
  peer.close(1008, message);
}
