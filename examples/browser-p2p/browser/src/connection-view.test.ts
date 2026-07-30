import { expect, test } from "bun:test";
import { connectionView } from "./connection-view";

test("identifies a peer disconnect after an authenticated connection", () => {
  expect(connectionView("connected", "disconnected")).toEqual({
    canSend: false,
    label: "Disconnected",
    peerDisconnected: true,
  });
});

test("does not present an initial connection failure as a peer disconnect", () => {
  expect(connectionView("connecting", "disconnected").peerDisconnected).toBeFalse();
});
