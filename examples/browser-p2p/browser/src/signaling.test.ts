import { describe, expect, test } from "bun:test";
import { createInvite } from "./invite";
import { SignalingCipher } from "./signaling";

describe("encrypted signaling envelopes", () => {
  test("authenticates role, session, content, and monotonic sequence", async () => {
    const invite = createInvite("11".repeat(32));
    const initiator = new SignalingCipher(invite.session, invite.secret, "initiator");
    const responder = new SignalingCipher(invite.session, invite.secret, "responder");
    const envelope = await initiator.seal({ type: "identity", publicKey: "22".repeat(32) });

    await expect(responder.open(envelope)).resolves.toEqual({
      type: "identity",
      publicKey: "22".repeat(32),
    });
    await expect(responder.open(envelope)).rejects.toThrow("out of sequence");
  });

  test("rejects tampering and the wrong pairing secret", async () => {
    const invite = createInvite("33".repeat(32));
    const sender = new SignalingCipher(invite.session, invite.secret, "initiator");
    const wrongInvite = createInvite("44".repeat(32));
    const receiver = new SignalingCipher(invite.session, wrongInvite.secret, "responder");
    const envelope = await sender.seal({ type: "candidate", candidate: { candidate: "candidate:1" } });

    await expect(receiver.open(envelope)).rejects.toThrow("authenticated");
  });
});
