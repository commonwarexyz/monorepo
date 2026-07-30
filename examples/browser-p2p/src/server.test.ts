import { describe, expect, test } from "bun:test";
import { join, sep } from "node:path";
import {
  cacheControl,
  parseIceServers,
  RateLimiter,
  resolveStaticPath,
  selectApplicationUrl,
} from "./server";

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

test("does not cache generated WASM under stable filenames", () => {
  expect(cacheControl("/wasm/browser_p2p.js")).toBe("no-store");
  expect(cacheControl("/wasm/browser_p2p_bg.wasm")).toBe("no-store");
});

describe("ICE configuration", () => {
  test("provides STUN discovery by default", () => {
    expect(parseIceServers(undefined)).toEqual([
      { urls: "stun:stun.cloudflare.com:3478" },
    ]);
  });

  test("allows isolated same-LAN testing without an ICE server", () => {
    expect(parseIceServers("[]")).toEqual([]);
  });
});

test("rate limiter releases expired keys", () => {
  const limiter = new RateLimiter(1, 1_000);
  expect(limiter.allow("peer", 0)).toBeTrue();
  expect(limiter.size).toBe(1);

  limiter.cleanup(1_000);

  expect(limiter.size).toBe(0);
});
