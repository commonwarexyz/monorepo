import { describe, expect, test } from "bun:test";
import { join, sep } from "node:path";
import { resolveStaticPath, selectApplicationUrl } from "./server";

describe("static application paths", () => {
  test("serves the application root when the dist directory has a trailing separator", () => {
    const root = join("/tmp", "commonware-browser-dist") + sep;

    expect(resolveStaticPath(root, "/")).toBe(join(root, "index.html"));
  });

  test("rejects paths outside the packaged application", () => {
    const root = join("/tmp", "commonware-browser-dist") + sep;

    expect(resolveStaticPath(root, "/../secret")).toBeUndefined();
  });
});

describe("application URL", () => {
  test("prefers an explicitly configured public URL", () => {
    expect(selectApplicationUrl(
      "https://chat.example.com/pair/",
      "http",
      3000,
      ["192.168.1.42"],
    )).toBe("https://chat.example.com/pair/");
  });

  test("uses a phone-reachable LAN address instead of localhost", () => {
    expect(selectApplicationUrl(
      undefined,
      "http",
      3000,
      ["127.0.0.1", "192.168.1.42"],
    )).toBe("http://192.168.1.42:3000/");
  });
});
