import { expect, test } from "bun:test";
import { copyText } from "./clipboard";

test("falls back when the secure clipboard API is unavailable", async () => {
  let copied = "";

  await copyText("one-time invite", null, (text) => {
    copied = text;
    return true;
  });

  expect(copied).toBe("one-time invite");
});

test("reports a failed legacy copy", async () => {
  expect(copyText("public key", null, () => false)).rejects.toThrow("Could not copy to the clipboard.");
});

test("prefers the secure clipboard API", async () => {
  const writes: string[] = [];
  await copyText(
    "public key",
    { writeText: async (text) => void writes.push(text) },
    () => {
      throw new Error("legacy copy should not run");
    },
  );

  expect(writes).toEqual(["public key"]);
});
