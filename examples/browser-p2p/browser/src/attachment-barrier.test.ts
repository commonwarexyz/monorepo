import { describe, expect, test } from "bun:test";
import { AttachmentBarrier } from "./attachment-barrier";

describe("Commonware attachment barrier", () => {
  test("starts only after the local adapter and remote adapter are ready", () => {
    const barrier = new AttachmentBarrier();

    expect(barrier.markRemoteReady()).toBe(false);
    expect(barrier.markLocalReady()).toBe(true);
    expect(barrier.markLocalReady()).toBe(false);
    expect(barrier.markRemoteReady()).toBe(false);
  });

  test("works when the local adapter is installed first", () => {
    const barrier = new AttachmentBarrier();

    expect(barrier.markLocalReady()).toBe(false);
    expect(barrier.markRemoteReady()).toBe(true);
  });
});
