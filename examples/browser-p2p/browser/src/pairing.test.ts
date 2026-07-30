import { describe, expect, test } from "bun:test";
import { parsePairingPayload } from "./pairing";

const payload = {
  version: 1 as const,
  desktop_public_key: "a".repeat(64),
  websocket_url: "wss://desktop.example.com/pair",
  capability: "a".repeat(43),
  session_id: "b".repeat(22),
  expires_at: Math.floor(Date.now() / 1_000) + 60,
};

describe("parsePairingPayload", () => {
  test("parses canonical JSON", () => {
    expect(parsePairingPayload(JSON.stringify(payload))).toEqual(payload);
  });

  test("parses an invite URL", () => {
    const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const invite = `https://chat.example.com/#pair=${encoded}`;
    expect(parsePairingPayload(invite)).toEqual(payload);
  });

  test("allows plain WebSockets for LAN pairing", () => {
    const local = { ...payload, websocket_url: "ws://localhost:8080" };
    expect(parsePairingPayload(JSON.stringify(local)).websocket_url).toBe("ws://localhost:8080/");

    const lan = { ...payload, websocket_url: "ws://192.168.1.42:8080/pair" };
    expect(parsePairingPayload(JSON.stringify(lan)).websocket_url).toBe(
      "ws://192.168.1.42:8080/pair",
    );
  });

  test("rejects non-WebSocket pairing endpoints", () => {
    const http = { ...payload, websocket_url: "http://192.168.1.42:8080/pair" };
    expect(() => parsePairingPayload(JSON.stringify(http))).toThrow("must use WebSockets");
  });

  test("rejects invalid public keys", () => {
    expect(() =>
      parsePairingPayload(JSON.stringify({ ...payload, desktop_public_key: "not-a-key" })),
    ).toThrow("invalid Ed25519 public key");
  });

  test("rejects expired sessions and short capabilities", () => {
    expect(() =>
      parsePairingPayload(
        JSON.stringify({ ...payload, expires_at: Math.floor(Date.now() / 1_000) - 1 }),
      ),
    ).toThrow("expired");
    expect(() =>
      parsePairingPayload(JSON.stringify({ ...payload, capability: "too-short" })),
    ).toThrow("256-bit capability");
  });
});
