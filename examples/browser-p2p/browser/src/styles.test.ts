import { expect, test } from "bun:test";

test("uses a slow status pulse", async () => {
  const stylesheet = await Bun.file(new URL("./styles.css", import.meta.url)).text();
  const duration = stylesheet.match(/--status-pulse-duration:\s*([\d.]+)s/)?.[1];

  expect(Number(duration)).toBeGreaterThanOrEqual(4);
});
