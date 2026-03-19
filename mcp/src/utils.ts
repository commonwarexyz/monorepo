/**
 * Utility functions for Commonware MCP
 */

/**
 * Sort versions in descending order (newest first).
 * Handles semantic versioning like v0.0.64, v0.0.63, v0.0.62
 */
export function sortVersionsDesc(versions: string[]): void {
  versions.sort((a, b) => {
    const partsA = a.replace(/^v/, "").split(".").map(Number);
    const partsB = b.replace(/^v/, "").split(".").map(Number);
    for (let i = 0; i < 3; i++) {
      if (partsA[i] !== partsB[i]) {
        return partsB[i] - partsA[i];
      }
    }
    return 0;
  });
}

/**
 * Get the language identifier for syntax highlighting based on file extension.
 */
export function getLanguage(path: string): string {
  if (path.endsWith(".rs")) {
    return "rust";
  }
  if (path.endsWith(".toml")) {
    return "toml";
  }
  if (path.endsWith(".md")) {
    return "markdown";
  }
  return "";
}

/**
 * Strip the commonware- prefix from a crate name or path.
 * Crate names use commonware-* but folder paths don't have the prefix.
 */
export function stripCratePrefix(name: string): string {
  return name.replace(/^commonware-/, "");
}

/**
 * Validate a file path - no path traversal or absolute paths allowed.
 */
export function isValidPath(path: string): boolean {
  if (path.includes("..")) {
    return false;
  }
  if (path.startsWith("/")) {
    return false;
  }
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
 * Parse workspace member paths from a Cargo.toml content string.
 * Returns folder paths (e.g., "cryptography", "examples/chat"), not crate names.
 * Use parseCrateInfo to get the actual crate name from each member's Cargo.toml.
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
 * Only matches fields within the [package] section to avoid matching
 * fields in [dependencies] or other sections.
 */
export function parseCrateInfo(
  cargoToml: string,
  fallbackPath: string
): { name: string; description: string } {
  // Extract the [package] section (ends at next [...] section or EOF)
  const packageMatch = cargoToml.match(/\[package\]([\s\S]*?)(?=\n\[|$)/);
  const packageSection = packageMatch ? packageMatch[1] : "";

  const nameMatch = packageSection.match(/name\s*=\s*"([^"]+)"/);
  const name = nameMatch ? nameMatch[1] : fallbackPath;

  const descMatch = packageSection.match(/description\s*=\s*"([^"]+)"/);
  const description = descMatch ? descMatch[1] : "No description available";

  return { name, description };
}

/**
 * Represents a snippet of consecutive lines with content.
 */
export interface Snippet {
  start: number; // First line index (0-based)
  end: number; // One past last line index (exclusive)
  score: number; // Cumulative score of all lines
}

/**
 * Build snippets using a rolling window approach.
 * Creates a window centered on each line with a positive score,
 * allowing overlapping windows that will be filtered later.
 * Only stores metadata (line span + score), not the actual text.
 */
export function buildSnippets(lineScores: number[], windowSize: number = 7): Snippet[] {
  const snippets: Snippet[] = [];
  const halfWindow = Math.floor(windowSize / 2);
  const totalLines = lineScores.length;

  for (let lineNum = 0; lineNum < totalLines; lineNum++) {
    // Only create windows centered on lines with matches
    if (lineScores[lineNum] <= 0) {
      continue;
    }

    // Create window centered on this line
    const start = Math.max(0, lineNum - halfWindow);
    const end = Math.min(totalLines, lineNum + halfWindow + 1);

    // Calculate total score for this window
    let totalScore = 0;
    for (let i = start; i < end; i++) {
      totalScore += lineScores[i];
    }

    snippets.push({ start, end, score: totalScore });
  }

  return snippets;
}

/**
 * Check if a candidate snippet has majority overlap with a selected snippet.
 * Returns true if more than half of the candidate snippet's lines overlap
 * with the selected snippet.
 */
export function hasMajorityOverlap(
  candidateStart: number,
  candidateEnd: number,
  selectedStart: number,
  selectedEnd: number
): boolean {
  const overlapStart = Math.max(candidateStart, selectedStart);
  const overlapEnd = Math.min(candidateEnd, selectedEnd);
  const overlapCount = Math.max(0, overlapEnd - overlapStart);
  const candidateSize = candidateEnd - candidateStart;
  return overlapCount > candidateSize / 2;
}

/**
 * Select top snippets while filtering out those with majority overlap.
 * Skips snippets with a score of 0.
 */
export function selectTopSnippets(
  snippets: Snippet[],
  maxSnippets: number
): Array<{ start: number; end: number }> {
  // Sort by score descending, filter out zero-score snippets
  const sorted = [...snippets].filter((s) => s.score > 0).sort((a, b) => b.score - a.score);

  const selected: Array<{ start: number; end: number }> = [];

  for (const snippet of sorted) {
    if (selected.length >= maxSnippets) {
      break;
    }

    const { start, end } = snippet;

    // Check for majority overlap with already selected snippets
    let hasOverlap = false;
    for (const sel of selected) {
      if (hasMajorityOverlap(start, end, sel.start, sel.end)) {
        hasOverlap = true;
        break;
      }
    }

    if (!hasOverlap) {
      selected.push({ start, end });
    }
  }

  return selected;
}

/**
 * Format a snippet as a string with line numbers.
 * Line numbers are 0-indexed to match formatWithLineNumbers.
 */
export function formatSnippet(lines: string[], start: number, end: number): string {
  return lines
    .slice(start, end)
    .map((l, idx) => `${start + idx}: ${l}`)
    .join("\n");
}

/**
 * Format file content with line numbers.
 * Line numbers are 0-indexed to match search_code output.
 * If startLine/endLine are provided, only that range is returned.
 */
export function formatWithLineNumbers(
  content: string,
  startLine?: number,
  endLine?: number
): string {
  const lines = content.split("\n");

  // Determine range (0-indexed, inclusive)
  const start = startLine !== undefined ? Math.max(0, startLine) : 0;
  const end = endLine !== undefined ? Math.min(lines.length - 1, endLine) : lines.length - 1;

  // Validate range
  if (start > end || start >= lines.length) {
    return "";
  }

  // Extract and format lines (inclusive range)
  return lines
    .slice(start, end + 1)
    .map((line, idx) => `${start + idx}: ${line}`)
    .join("\n");
}

/**
 * Build a file tree string from a list of file paths.
 * Groups files by directory and formats as an indented tree.
 */
export function buildFileTree(files: string[], prefix: string): string {
  // Remove prefix and organize into tree
  const tree: Map<string, string[]> = new Map();

  for (const file of files) {
    const relative = file.slice(prefix.length);
    const parts = relative.split("/");
    const dir = parts.length > 1 ? parts.slice(0, -1).join("/") : ".";
    const filename = parts[parts.length - 1];

    if (!tree.has(dir)) {
      tree.set(dir, []);
    }
    tree.get(dir)!.push(filename);
  }

  // Build output
  const lines: string[] = [];
  const sortedDirs = [...tree.keys()].sort();

  for (const dir of sortedDirs) {
    if (dir !== ".") {
      lines.push(`${dir}/`);
    }
    const filesInDir = tree.get(dir)!.sort();
    for (const file of filesInDir) {
      if (dir === ".") {
        lines.push(file);
      } else {
        lines.push(`  ${file}`);
      }
    }
  }

  return lines.join("\n");
}
