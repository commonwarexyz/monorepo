/**
 * Utility functions for the Commonware MCP Server
 *
 * Extracted for testability and reuse.
 */

/**
 * Simple LRU cache with a maximum entry count.
 * Uses Map's insertion order to track recency.
 */
export class LRUCache<T> {
  private cache: Map<string, T>;
  private maxSize: number;

  constructor(maxSize: number) {
    this.cache = new Map();
    this.maxSize = maxSize;
  }

  get(key: string): T | undefined {
    const value = this.cache.get(key);
    if (value !== undefined) {
      // Move to end (most recently used)
      this.cache.delete(key);
      this.cache.set(key, value);
    }
    return value;
  }

  set(key: string, value: T): void {
    // If key exists, delete it first to update position
    if (this.cache.has(key)) {
      this.cache.delete(key);
    }
    this.cache.set(key, value);

    // Evict oldest entries if over limit
    while (this.cache.size > this.maxSize) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) {
        this.cache.delete(oldest);
      }
    }
  }

  get size(): number {
    return this.cache.size;
  }

  clear(): void {
    this.cache.clear();
  }
}

/**
 * Sort versions in descending order (newest first).
 * Handles semantic versioning like v0.0.64, v0.0.63, v0.0.62
 */
export function sortVersionsDesc(versions: string[]): void {
  versions.sort((a, b) => {
    const partsA = a.replace(/^v/, "").split(".").map(Number);
    const partsB = b.replace(/^v/, "").split(".").map(Number);
    for (let i = 0; i < 3; i++) {
      if (partsA[i] !== partsB[i]) return partsB[i] - partsA[i];
    }
    return 0;
  });
}

/**
 * Get the language identifier for syntax highlighting based on file extension.
 */
export function getLanguage(path: string): string {
  if (path.endsWith(".rs")) return "rust";
  if (path.endsWith(".toml")) return "toml";
  if (path.endsWith(".md")) return "markdown";
  return "";
}

/**
 * Validate a file path - no path traversal or absolute paths allowed.
 */
export function isValidPath(path: string): boolean {
  if (path.includes("..")) return false;
  if (path.startsWith("/")) return false;
  return true;
}

/**
 * Parse versions and files from sitemap XML.
 */
export function parseSitemap(xml: string): { versions: string[]; files: Map<string, string[]> } {
  const versions: string[] = [];
  const files = new Map<string, string[]>();

  const urlMatches = xml.matchAll(/<loc>([^<]+)<\/loc>/g);
  for (const match of urlMatches) {
    const url = match[1];

    // Extract version from /code/vX.X.X/ paths
    const codeMatch = url.match(/\/code\/(v[\d.]+)\/(.+)$/);
    if (codeMatch) {
      const [, version, path] = codeMatch;
      if (!versions.includes(version)) {
        versions.push(version);
      }
      if (!files.has(version)) {
        files.set(version, []);
      }
      files.get(version)!.push(path);
    }
  }

  sortVersionsDesc(versions);
  return { versions, files };
}

/**
 * Parse workspace members from a Cargo.toml content string.
 */
export function parseWorkspaceMembers(cargoToml: string): string[] {
  const membersMatch = cargoToml.match(/members\s*=\s*\[([\s\S]*?)\]/);
  if (!membersMatch) {
    return [];
  }

  const membersBlock = membersMatch[1];
  const memberPaths: string[] = [];

  const pathMatches = membersBlock.matchAll(/"([^"]+)"/g);
  for (const match of pathMatches) {
    memberPaths.push(match[1]);
  }

  return memberPaths;
}

/**
 * Parse package name and description from a crate's Cargo.toml.
 */
export function parseCrateInfo(
  cargoToml: string,
  fallbackPath: string
): { name: string; description: string } {
  const nameMatch = cargoToml.match(/name\s*=\s*"([^"]+)"/);
  const name = nameMatch ? nameMatch[1].replace("commonware-", "") : fallbackPath;

  const descMatch = cargoToml.match(/description\s*=\s*"([^"]+)"/);
  const description = descMatch ? descMatch[1] : "No description available";

  return { name, description };
}
