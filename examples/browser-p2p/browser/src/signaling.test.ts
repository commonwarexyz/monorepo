import { describe, expect, test } from "bun:test";
import { createInvite } from "./invite";
import { SignalingCipher } from "./signaling";

const passthroughCipher = {
  seal: (_nonce: Uint8Array, _aad: Uint8Array, plaintext: Uint8Array) => plaintext,
  open: (_nonce: Uint8Array, _aad: Uint8Array, ciphertext: Uint8Array) => ciphertext,
};

const rejectingCipher = {
  ...passthroughCipher,
  open: () => {
    throw new Error("authentication failed");
  },
};

describe("encrypted signaling envelopes", () => {
  test("does not require secure-context Web Crypto", async () => {
    const browserCrypto = globalThis.crypto;
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: { getRandomValues: browserCrypto.getRandomValues.bind(browserCrypto) },
    });

    try {
      const invite = createInvite("00".repeat(32));
      const initiator = new SignalingCipher(invite.session, invite.secret, "initiator", passthroughCipher);
      const responder = new SignalingCipher(invite.session, invite.secret, "responder", passthroughCipher);
      const envelope = await initiator.seal({ type: "adapter-ready" });

      await expect(responder.open(envelope)).resolves.toEqual({ type: "adapter-ready" });
    } finally {
      Object.defineProperty(globalThis, "crypto", { configurable: true, value: browserCrypto });
    }
  });

  test("authenticates role, session, content, and monotonic sequence", async () => {
    const invite = createInvite("11".repeat(32));
    const initiator = new SignalingCipher(invite.session, invite.secret, "initiator", passthroughCipher);
    const responder = new SignalingCipher(invite.session, invite.secret, "responder", passthroughCipher);
    const envelope = await initiator.seal({ type: "identity", publicKey: "22".repeat(32) });

    await expect(responder.open(envelope)).resolves.toEqual({
      type: "identity",
      publicKey: "22".repeat(32),
    });
    await expect(responder.open(envelope)).rejects.toThrow("out of sequence");
  });

  test("rejects tampering and the wrong pairing secret", async () => {
    const invite = createInvite("33".repeat(32));
    const sender = new SignalingCipher(invite.session, invite.secret, "initiator", passthroughCipher);
    const wrongInvite = createInvite("44".repeat(32));
    const receiver = new SignalingCipher(invite.session, wrongInvite.secret, "responder", rejectingCipher);
    const envelope = await sender.seal({ type: "candidate", candidate: { candidate: "candidate:1" } });

    await expect(receiver.open(envelope)).rejects.toThrow("authenticated");
  });
});
