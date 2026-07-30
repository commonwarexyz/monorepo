import { expect, test } from "bun:test";

test("uses a slow status pulse", async () => {
  const stylesheet = await Bun.file(new URL("./styles.css", import.meta.url)).text();
  const duration = stylesheet.match(/--status-pulse-duration:\s*([\d.]+)s/)?.[1];

  expect(Number(duration)).toBeGreaterThanOrEqual(4);
});

test("supports system and explicit dark themes", async () => {
  const stylesheet = await Bun.file(new URL("./styles.css", import.meta.url)).text();

  expect(stylesheet).toContain('@media (prefers-color-scheme: dark)');
  expect(stylesheet).toContain(':root[data-theme="dark"]');
  expect(stylesheet).toContain("color-scheme: dark");
});

test("keeps the mobile chat inside the visual viewport", async () => {
  const stylesheet = await Bun.file(new URL("./styles.css", import.meta.url)).text();
  const mobile = stylesheet.slice(stylesheet.indexOf("@media (max-width: 600px)"));

  expect(mobile).toContain("height: var(--app-height)");
  expect(mobile).toContain("min-height: 0");
  expect(mobile).toContain("font-size: 16px");
  expect(mobile).toContain('.chat:focus-within .identity-panel');
  expect(mobile).toContain("minmax(0, 1fr)");
  expect(mobile).not.toContain("min-height: 540px");
});
