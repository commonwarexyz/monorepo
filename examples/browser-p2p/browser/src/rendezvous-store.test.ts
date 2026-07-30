import { describe, expect, test } from "bun:test";
import { RendezvousStore, type RendezvousLimits, type RendezvousPeer } from "./rendezvous-store";

const session = "s".repeat(43);
const limits: RendezvousLimits = {
  roomLifetimeMs: 100,
  replayLifetimeMs: 200,
  maxMessages: 2,
  maxBytes: 20,
  maxMessageBytes: 12,
  maxRooms: 2,
};

class Peer implements RendezvousPeer {
  messages: string[] = [];
  closes: Array<[number, string]> = [];
  send(message: string): void { this.messages.push(message); }
  close(code: number, reason: string): void { this.closes.push([code, reason]); }
}

describe("rendezvous rooms", () => {
  test("admits fixed roles, routes opaque payloads, and rejects third/replay", () => {
    let now = 0;
    const store = new RendezvousStore(limits, () => now);
    const initiator = new Peer();
    const responder = new Peer();
    expect(store.create(session, initiator)).toBe(true);
    expect(store.join(session, responder)).toBe(true);
    expect(store.relay(session, initiator, "opaque")).toBe(true);
    expect(responder.messages.at(-1)).toContain("opaque");

    const third = new Peer();
    expect(store.join(session, third)).toBe(false);
    expect(third.closes).toHaveLength(1);
    store.disconnect(responder);
    expect(store.create(session, new Peer())).toBe(false);

    now = 201;
    expect(store.create(session, new Peer())).toBe(true);
  });

  test("expires rooms and enforces count and byte bounds", () => {
    let now = 0;
    const store = new RendezvousStore(limits, () => now);
    const initiator = new Peer();
    const responder = new Peer();
    store.create(session, initiator);
    store.join(session, responder);
    expect(store.relay(session, initiator, "1234567890123")).toBe(false);
    expect(store.size).toBe(0);

    const other = "t".repeat(43);
    const waiting = new Peer();
    store.create(other, waiting);
    now = 100;
    store.cleanup();
    expect(store.size).toBe(0);
    expect(waiting.closes).toHaveLength(1);
  });
});
