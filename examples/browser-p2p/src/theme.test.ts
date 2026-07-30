import { expect, test } from "bun:test";
import { effectiveTheme, parseTheme } from "./theme";

test("uses the system theme without a saved preference", () => {
  expect(effectiveTheme(undefined, false)).toBe("light");
  expect(effectiveTheme(undefined, true)).toBe("dark");
});

test("a saved theme overrides the system preference", () => {
  expect(effectiveTheme("light", true)).toBe("light");
  expect(effectiveTheme("dark", false)).toBe("dark");
});

test("ignores invalid saved themes", () => {
  expect(parseTheme("light")).toBe("light");
  expect(parseTheme("dark")).toBe("dark");
  expect(parseTheme("sepia")).toBeUndefined();
  expect(parseTheme(null)).toBeUndefined();
});
