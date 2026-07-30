import { expect, test } from "bun:test";
import { RendezvousClient, type ServerEvent } from "./rendezvous";

const SESSION = "A".repeat(43);

class TestSocket extends EventTarget {
  readonly sent: string[] = [];
  readyState: number = WebSocket.OPEN;

  send(message: string): void {
    this.sent.push(message);
  }

  close(): void {
    this.readyState = WebSocket.CLOSED;
  }

  message(value: unknown): void {
    this.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(value) }));
  }
}

test("reports rendezvous closure after registration", async () => {
  const socket = new TestSocket();
  const client = new RendezvousClient(
    "ws://127.0.0.1/rendezvous",
    SESSION,
    "initiator",
    () => socket as unknown as WebSocket,
  );
  const events: ServerEvent[] = [];
  client.onEvent((event) => events.push(event));

  socket.dispatchEvent(new Event("open"));
  socket.message({ type: "ready" });
  await client.ready();
  socket.dispatchEvent(new Event("close"));

  expect(events.at(-1)).toEqual({
    type: "error",
    message: "The rendezvous connection closed.",
  });
});
