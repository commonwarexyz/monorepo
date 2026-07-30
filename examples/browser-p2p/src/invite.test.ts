import { describe, expect, test } from "bun:test";
import { createInvite, inviteUrl, parseInvite } from "./invite";

describe("invite fragments", () => {
  test("round trips a 256-bit session, secret, and initiator key", () => {
    const invite = createInvite("ab".repeat(32));
    const url = new URL(inviteUrl(invite, new URL("https://chat.example.test/room")));

    expect(url.search).toBe("");
    expect(parseInvite(url)).toEqual(invite);
    expect(invite.session).toHaveLength(43);
    expect(invite.secret).toHaveLength(43);
    expect(invite.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1_000));
  });

  test("rejects malformed, extra, and oversized fragments", () => {
    expect(() => parseInvite(new URL("https://chat.test/#v=1&s=short"))).toThrow();
    const invite = createInvite("cd".repeat(32));
    const url = new URL(inviteUrl(invite, new URL("https://chat.test/")));
    url.hash += "&extra=true";
    expect(() => parseInvite(url)).toThrow("unsupported fields");
    expect(() => parseInvite(new URL(`https://chat.test/#${"a".repeat(400)}`))).toThrow("too long");

    const expired = new URL(inviteUrl(invite, new URL("https://chat.test/")));
    const fields = new URLSearchParams(expired.hash.slice(1));
    fields.set("e", "1");
    expired.hash = fields.toString();
    expect(() => parseInvite(expired)).toThrow("expired");
  });
});
