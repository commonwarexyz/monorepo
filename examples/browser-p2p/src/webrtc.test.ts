import { expect, test } from "bun:test";

test("does not time out an idle initiator", async () => {
  const source = await Bun.file(new URL("./webrtc.ts", import.meta.url)).text();
  const constructor = source.slice(
    source.indexOf("  constructor(options:"),
    source.indexOf("\n  async start(): Promise<void>"),
  );

  expect(constructor).not.toContain("setTimeout");
});
