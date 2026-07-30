import { describe, expect, test } from "bun:test";
import { join, sep } from "node:path";
import { resolveStaticPath } from "./server";

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
