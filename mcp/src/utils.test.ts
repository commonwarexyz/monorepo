import { describe, expect, it } from "vitest";
import {
  sortVersionsDesc,
  getLanguage,
  stripCratePrefix,
  isValidPath,
  parseSitemap,
  parseWorkspaceMembers,
  parseCrateInfo,
  buildFileTree,
  formatWithLineNumbers,
} from "./utils.ts";

describe("sortVersionsDesc", () => {
  it("should sort versions in descending order", () => {
    const versions = ["v0.0.62", "v0.0.64", "v0.0.63"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["v0.0.64", "v0.0.63", "v0.0.62"]);
  });

  it("should handle versions without v prefix", () => {
    const versions = ["0.0.62", "0.0.64", "0.0.63"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["0.0.64", "0.0.63", "0.0.62"]);
  });

  it("should handle mixed v prefix versions", () => {
    const versions = ["v0.0.62", "0.0.64", "v0.0.63"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["0.0.64", "v0.0.63", "v0.0.62"]);
  });

  it("should handle major version differences", () => {
    const versions = ["v1.0.0", "v0.0.64", "v2.0.0"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["v2.0.0", "v1.0.0", "v0.0.64"]);
  });

  it("should handle minor version differences", () => {
    const versions = ["v0.1.0", "v0.2.0", "v0.0.64"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["v0.2.0", "v0.1.0", "v0.0.64"]);
  });

  it("should handle empty array", () => {
    const versions: string[] = [];
    sortVersionsDesc(versions);
    expect(versions).toEqual([]);
  });

  it("should handle single version", () => {
    const versions = ["v0.0.64"];
    sortVersionsDesc(versions);
    expect(versions).toEqual(["v0.0.64"]);
  });
});

describe("getLanguage", () => {
  it("should return rust for .rs files", () => {
    expect(getLanguage("src/lib.rs")).toBe("rust");
    expect(getLanguage("cryptography/src/bls12381/mod.rs")).toBe("rust");
  });

  it("should return toml for .toml files", () => {
    expect(getLanguage("Cargo.toml")).toBe("toml");
    expect(getLanguage("cryptography/Cargo.toml")).toBe("toml");
  });

  it("should return markdown for .md files", () => {
    expect(getLanguage("README.md")).toBe("markdown");
    expect(getLanguage("docs/CONTRIBUTING.md")).toBe("markdown");
  });

  it("should return empty string for unknown extensions", () => {
    expect(getLanguage("file.txt")).toBe("");
    expect(getLanguage("file.json")).toBe("");
    expect(getLanguage("file")).toBe("");
  });
});

describe("stripCratePrefix", () => {
  it("should strip commonware- prefix from crate names", () => {
    expect(stripCratePrefix("commonware-cryptography")).toBe("cryptography");
    expect(stripCratePrefix("commonware-broadcast")).toBe("broadcast");
    expect(stripCratePrefix("commonware-p2p")).toBe("p2p");
  });

  it("should strip prefix from paths", () => {
    expect(stripCratePrefix("commonware-cryptography/src/lib.rs")).toBe("cryptography/src/lib.rs");
  });

  it("should not modify names without prefix", () => {
    expect(stripCratePrefix("chat")).toBe("chat");
    expect(stripCratePrefix("bridge")).toBe("bridge");
    expect(stripCratePrefix("cryptography")).toBe("cryptography");
  });

  it("should only strip prefix at start", () => {
    expect(stripCratePrefix("foo-commonware-bar")).toBe("foo-commonware-bar");
  });
});

describe("isValidPath", () => {
  it("should accept valid relative paths", () => {
    expect(isValidPath("cryptography/src/lib.rs")).toBe(true);
    expect(isValidPath("README.md")).toBe(true);
    expect(isValidPath("examples/chat/src/main.rs")).toBe(true);
  });

  it("should reject paths with path traversal", () => {
    expect(isValidPath("../etc/passwd")).toBe(false);
    expect(isValidPath("cryptography/../../../etc/passwd")).toBe(false);
    expect(isValidPath("..")).toBe(false);
  });

  it("should reject absolute paths", () => {
    expect(isValidPath("/etc/passwd")).toBe(false);
    expect(isValidPath("/home/user/file.rs")).toBe(false);
  });

  it("should accept paths with dots that are not traversal", () => {
    expect(isValidPath(".gitignore")).toBe(true);
    expect(isValidPath("src/.hidden/file.rs")).toBe(true);
    expect(isValidPath("file.test.rs")).toBe(true);
  });
});

describe("parseSitemap", () => {
  it("should parse versions and files from sitemap XML", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://commonware.xyz/code/v0.0.64/README.md</loc>
  </url>
  <url>
    <loc>https://commonware.xyz/code/v0.0.64/cryptography/src/lib.rs</loc>
  </url>
  <url>
    <loc>https://commonware.xyz/code/v0.0.63/README.md</loc>
  </url>
</urlset>`;

    const result = parseSitemap(xml);

    expect(result.versions).toEqual(["v0.0.64", "v0.0.63"]);
    expect(result.files.get("v0.0.64")).toEqual(["README.md", "cryptography/src/lib.rs"]);
    expect(result.files.get("v0.0.63")).toEqual(["README.md"]);
  });

  it("should sort versions in descending order", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://commonware.xyz/code/v0.0.62/README.md</loc>
  </url>
  <url>
    <loc>https://commonware.xyz/code/v0.0.64/README.md</loc>
  </url>
  <url>
    <loc>https://commonware.xyz/code/v0.0.63/README.md</loc>
  </url>
</urlset>`;

    const result = parseSitemap(xml);
    expect(result.versions).toEqual(["v0.0.64", "v0.0.63", "v0.0.62"]);
  });

  it("should handle empty sitemap", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
</urlset>`;

    const result = parseSitemap(xml);
    expect(result.versions).toEqual([]);
    expect(result.files.size).toBe(0);
  });

  it("should ignore non-code URLs", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://commonware.xyz/index.html</loc>
  </url>
  <url>
    <loc>https://commonware.xyz/blog/post.html</loc>
  </url>
  <url>
    <loc>https://commonware.xyz/code/v0.0.64/README.md</loc>
  </url>
</urlset>`;

    const result = parseSitemap(xml);
    expect(result.versions).toEqual(["v0.0.64"]);
    expect(result.files.get("v0.0.64")).toEqual(["README.md"]);
  });
});

describe("parseWorkspaceMembers", () => {
  it("should parse workspace members from Cargo.toml", () => {
    const cargoToml = `[workspace]
members = [
    "broadcast",
    "codec",
    "cryptography",
    "examples/chat",
]
resolver = "2"`;

    const members = parseWorkspaceMembers(cargoToml);
    expect(members).toEqual(["broadcast", "codec", "cryptography", "examples/chat"]);
  });

  it("should handle empty members array", () => {
    const cargoToml = `[workspace]
members = []
resolver = "2"`;

    const members = parseWorkspaceMembers(cargoToml);
    expect(members).toEqual([]);
  });

  it("should return empty array for invalid Cargo.toml", () => {
    const cargoToml = `[package]
name = "some-crate"
version = "0.1.0"`;

    const members = parseWorkspaceMembers(cargoToml);
    expect(members).toEqual([]);
  });

  it("should handle inline members array", () => {
    const cargoToml = `[workspace]
members = ["broadcast", "codec"]`;

    const members = parseWorkspaceMembers(cargoToml);
    expect(members).toEqual(["broadcast", "codec"]);
  });
});

describe("parseCrateInfo", () => {
  it("should parse crate name and description", () => {
    const cargoToml = `[package]
name = "commonware-cryptography"
edition.workspace = true
description = "Generate keys, sign arbitrary messages, and deterministically verify signatures."`;

    const info = parseCrateInfo(cargoToml, "cryptography");
    expect(info.name).toBe("commonware-cryptography");
    expect(info.description).toBe(
      "Generate keys, sign arbitrary messages, and deterministically verify signatures."
    );
  });

  it("should preserve commonware- prefix in name", () => {
    const cargoToml = `[package]
name = "commonware-broadcast"
description = "Disseminate data over a wide-area network."`;

    const info = parseCrateInfo(cargoToml, "broadcast");
    expect(info.name).toBe("commonware-broadcast");
  });

  it("should use fallback path when name is missing", () => {
    const cargoToml = `[package]
edition = "2021"
description = "Some description"`;

    const info = parseCrateInfo(cargoToml, "fallback-path");
    expect(info.name).toBe("fallback-path");
  });

  it("should use default description when missing", () => {
    const cargoToml = `[package]
name = "commonware-test"`;

    const info = parseCrateInfo(cargoToml, "test");
    expect(info.description).toBe("No description available");
  });

  it("should handle example crates without commonware prefix", () => {
    const cargoToml = `[package]
name = "chat"
description = "Send encrypted messages to a group of friends."`;

    const info = parseCrateInfo(cargoToml, "examples/chat");
    expect(info.name).toBe("chat");
    expect(info.description).toBe("Send encrypted messages to a group of friends.");
  });

  it("should only match name in [package] section, not dependencies", () => {
    const cargoToml = `[dependencies]
some-crate = { version = "1.0", package = "actual-name" }

[dependencies.renamed]
name = "wrong-name"
version = "1.0"

[package]
name = "correct-name"
description = "The correct description"

[dev-dependencies]
test-crate = { name = "also-wrong" }`;

    const info = parseCrateInfo(cargoToml, "fallback");
    expect(info.name).toBe("correct-name");
    expect(info.description).toBe("The correct description");
  });
});

describe("buildFileTree", () => {
  it("should build tree from files with prefix", () => {
    const files = [
      "cryptography/src/lib.rs",
      "cryptography/src/bls12381/mod.rs",
      "cryptography/src/bls12381/keys.rs",
      "cryptography/Cargo.toml",
      "cryptography/README.md",
    ];
    const result = buildFileTree(files, "cryptography/");

    expect(result).toBe(
      `Cargo.toml
README.md
src/
  lib.rs
src/bls12381/
  keys.rs
  mod.rs`
    );
  });

  it("should handle files only in root directory", () => {
    const files = ["crate/Cargo.toml", "crate/README.md", "crate/LICENSE"];
    const result = buildFileTree(files, "crate/");

    expect(result).toBe(`Cargo.toml
LICENSE
README.md`);
  });

  it("should handle deeply nested directories", () => {
    const files = ["pkg/src/a/b/c/deep.rs", "pkg/src/a/b/shallow.rs", "pkg/src/a/top.rs"];
    const result = buildFileTree(files, "pkg/");

    expect(result).toBe(
      `src/a/
  top.rs
src/a/b/
  shallow.rs
src/a/b/c/
  deep.rs`
    );
  });

  it("should sort directories and files alphabetically", () => {
    const files = [
      "pkg/src/zebra.rs",
      "pkg/src/alpha.rs",
      "pkg/tests/z_test.rs",
      "pkg/tests/a_test.rs",
    ];
    const result = buildFileTree(files, "pkg/");

    expect(result).toBe(
      `src/
  alpha.rs
  zebra.rs
tests/
  a_test.rs
  z_test.rs`
    );
  });

  it("should handle empty file list", () => {
    const result = buildFileTree([], "pkg/");
    expect(result).toBe("");
  });

  it("should handle single file", () => {
    const files = ["pkg/README.md"];
    const result = buildFileTree(files, "pkg/");
    expect(result).toBe("README.md");
  });
});

describe("formatWithLineNumbers", () => {
  const sampleContent = `fn main() {
    println!("Hello, world!");
}

fn helper() {
    // do something
}`;

  it("should format entire file with line numbers (0-indexed)", () => {
    const result = formatWithLineNumbers(sampleContent);
    // Note: empty line 3 produces "3: " with trailing space from the format string
    const expected = [
      "0: fn main() {",
      '1:     println!("Hello, world!");',
      "2: }",
      "3: ",
      "4: fn helper() {",
      "5:     // do something",
      "6: }",
    ].join("\n");
    expect(result).toBe(expected);
  });

  it("should format a range of lines (start_line only)", () => {
    const result = formatWithLineNumbers(sampleContent, 4);
    expect(result).toBe(`4: fn helper() {
5:     // do something
6: }`);
  });

  it("should format a range of lines (end_line only)", () => {
    const result = formatWithLineNumbers(sampleContent, undefined, 2);
    expect(result).toBe(`0: fn main() {
1:     println!("Hello, world!");
2: }`);
  });

  it("should format a range of lines (both start and end)", () => {
    const result = formatWithLineNumbers(sampleContent, 1, 3);
    // Note: line 3 is empty, produces "3: " with trailing space
    const expected = ['1:     println!("Hello, world!");', "2: }", "3: "].join("\n");
    expect(result).toBe(expected);
  });

  it("should clamp start_line to 0", () => {
    const result = formatWithLineNumbers(sampleContent, -5, 1);
    expect(result).toBe(`0: fn main() {
1:     println!("Hello, world!");`);
  });

  it("should clamp end_line to last line index", () => {
    const result = formatWithLineNumbers(sampleContent, 4, 100);
    expect(result).toBe(`4: fn helper() {
5:     // do something
6: }`);
  });

  it("should return empty string if start > end", () => {
    const result = formatWithLineNumbers(sampleContent, 5, 2);
    expect(result).toBe("");
  });

  it("should return empty string if start >= total lines", () => {
    const result = formatWithLineNumbers(sampleContent, 100);
    expect(result).toBe("");
  });

  it("should handle single line file", () => {
    const result = formatWithLineNumbers("single line");
    expect(result).toBe("0: single line");
  });

  it("should handle empty content", () => {
    const result = formatWithLineNumbers("");
    expect(result).toBe("0: ");
  });

  it("should use 0-indexed line numbers matching search_code", () => {
    const content = "line one\nline two\nline three";
    const result = formatWithLineNumbers(content, 1, 1);
    expect(result).toBe("1: line two");
  });
});
