/**
 * Commonware MCP
 *
 * A Model Context Protocol server for the Commonware Library that exposes
 * source code to AI assistants like Claude, Cursor, etc.
 *
 * Tools:
 * - get_file: Retrieve a specific file by path
 * - search_code: Search across source code files
 * - list_versions: List available code versions
 * - list_crates: List all crates in the workspace (from Cargo.toml)
 * - get_crate_readme: Get the README for a specific crate
 * - get_overview: Get the repository overview
 * - list_files: List files in a crate or directory
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Env } from "./env.d.ts";
import {
  buildFileTree,
  getLanguage,
  isValidPath,
  parseSitemap,
  parseWorkspaceMembers,
  parseCrateInfo,
  stripCratePrefix,
} from "./utils.ts";
import pkg from "../package.json";

// Types
interface CrateInfo {
  name: string;
  path: string;
  description: string;
}

interface SitemapData {
  versions: string[];
  files: Record<string, string[]>; // version -> file paths (JSON-serializable)
}

// Search index entry: file path and its full content
interface SearchIndexEntry {
  file: string;
  content: string;
}

// Full search index for a version
type SearchIndex = SearchIndexEntry[];

// Constants
const FILE_CACHE_TTL = 60 * 60 * 24 * 365; // 1 year (versioned files are immutable)
const SITEMAP_CACHE_TTL = 60 * 60; // 1 hour
const MAX_SEARCH_RESULTS = 50;
const INDEX_BUILD_BATCH_SIZE = 50; // Larger batches for index building (one-time cost)
const SEARCH_INDEX_EXTENSIONS = new Set(["rs", "md", "toml"]); // File types to index

export class CommonwareMCP extends McpAgent<Env, {}, {}> {
  server!: McpServer;

  async init() {
    this.server = new McpServer({
      name: "commonware-library",
      version: pkg.version,
    });

    // Tool: Get a specific file by path
    this.server.tool(
      "get_file",
      "Retrieve a file from the Commonware repository by its path. " +
        "Paths should be relative to the repository root (e.g., 'commonware-cryptography/src/lib.rs'). " +
        "Optionally specify a version (e.g., 'v0.0.64'), defaults to latest.",
      {
        path: z
          .string()
          .describe(
            "File path relative to repository root, e.g., 'commonware-cryptography/src/lib.rs'"
          ),
        version: z
          .string()
          .optional()
          .describe("Version tag (e.g., 'v0.0.64'). Defaults to latest."),
      },
      async ({ path, version }) => {
        // Basic path validation - no path traversal
        if (!isValidPath(path)) {
          return {
            content: [{ type: "text", text: `Error: Invalid path '${path}'` }],
            isError: true,
          };
        }

        // Strip commonware- prefix from path if present (folders don't have it)
        const normalizedPath = stripCratePrefix(path);

        const ver = version || (await this.getLatestVersion());
        const content = await this.fetchFile(ver, normalizedPath);
        if (content === null) {
          return {
            content: [
              {
                type: "text",
                text: `Error: File not found at ${path} (version ${ver})`,
              },
            ],
            isError: true,
          };
        }

        return {
          content: [
            {
              type: "text",
              text: `# ${path} (${ver})\n\n\`\`\`${getLanguage(path)}\n${content}\n\`\`\``,
            },
          ],
        };
      }
    );

    // Tool: Search code files
    this.server.tool(
      "search_code",
      "Search for a pattern across source code files in the Commonware repository. " +
        "Returns matching files with relevant snippets. Useful for finding function definitions, " +
        "usage patterns, or understanding how features are implemented.",
      {
        query: z.string().describe("Search pattern (case-insensitive substring match)"),
        crate: z
          .string()
          .optional()
          .describe("Limit search to a specific crate (e.g., 'commonware-cryptography')"),
        file_type: z
          .enum(["rs", "md", "toml", "all"])
          .optional()
          .default("rs")
          .describe("File type to search: 'rs' for Rust, 'md' for markdown, 'toml', or 'all'"),
        version: z.string().optional().describe("Version tag. Defaults to latest."),
        max_results: z
          .number()
          .optional()
          .default(10)
          .describe(
            `Maximum number of results to return (default: 10, max: ${MAX_SEARCH_RESULTS})`
          ),
      },
      async ({ query, crate, file_type, version, max_results }) => {
        // Clamp max_results to prevent excessive fetching
        const limit = Math.min(max_results, MAX_SEARCH_RESULTS);

        const ver = version || (await this.getLatestVersion());

        // Get or build the search index (cached in Workers KV)
        const index = await this.getSearchIndex(ver);

        // Search the in-memory index
        const results = this.searchIndex(index, query, crate, file_type, limit);

        if (results.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No matches found for "${query}" in ${ver}${crate ? ` (crate: ${crate})` : ""}`,
              },
            ],
          };
        }

        const output = results
          .map(
            (r) =>
              `## ${r.file}\n\n\`\`\`${getLanguage(r.file)}\n${r.matches.join("\n---\n")}\n\`\`\``
          )
          .join("\n\n");

        return {
          content: [
            {
              type: "text",
              text: `# Search results for "${query}" (${ver})\n\nFound ${results.length} file(s):\n\n${output}`,
            },
          ],
        };
      }
    );

    // Tool: List available versions
    this.server.tool(
      "list_versions",
      "List all available versions of the Commonware Library source code.",
      {},
      async () => {
        const versions = await this.getVersions();
        return {
          content: [
            {
              type: "text",
              text:
                `# Available Versions\n\n` +
                versions.map((v, i) => `- ${v}${i === 0 ? " (latest)" : ""}`).join("\n"),
            },
          ],
        };
      }
    );

    // Tool: List crates (dynamically from Cargo.toml)
    this.server.tool(
      "list_crates",
      "List all crates (primitives) in the Commonware workspace with their descriptions.",
      {
        version: z.string().optional().describe("Version tag. Defaults to latest."),
      },
      async ({ version }) => {
        const ver = version || (await this.getLatestVersion());
        const crates = await this.getCrates(ver);

        if (crates.length === 0) {
          return {
            content: [{ type: "text", text: "Error: Could not fetch crate information" }],
            isError: true,
          };
        }

        const output = crates.map((c) => `- **${c.name}**: ${c.description}`).join("\n");

        return {
          content: [
            {
              type: "text",
              text: `# Commonware Crates (${ver})\n\n${output}\n\nUse \`get_crate_readme\` to get detailed documentation for any crate.`,
            },
          ],
        };
      }
    );

    // Tool: Get crate README
    this.server.tool(
      "get_crate_readme",
      "Get the README documentation for a specific Commonware crate.",
      {
        crate: z
          .string()
          .describe(
            "Crate name (e.g., 'commonware-cryptography', 'commonware-consensus', 'commonware-p2p')"
          ),
        version: z.string().optional().describe("Version tag. Defaults to latest."),
      },
      async ({ crate, version }) => {
        const ver = version || (await this.getLatestVersion());

        // Validate crate exists
        // Match by full name (commonware-*) or folder path
        const crates = await this.getCrates(ver);
        const folderName = stripCratePrefix(crate);
        const crateInfo = crates.find((c) => c.name === crate || c.path === folderName);
        if (!crateInfo) {
          const names = crates.map((c) => c.name).join(", ");
          return {
            content: [
              {
                type: "text",
                text: `Error: Unknown crate '${crate}'. Available crates: ${names}`,
              },
            ],
            isError: true,
          };
        }

        const content = await this.fetchFile(ver, `${crateInfo.path}/README.md`);
        if (content === null) {
          return {
            content: [
              {
                type: "text",
                text: `Error: README not found for crate '${crate}' (version ${ver})`,
              },
            ],
            isError: true,
          };
        }

        return {
          content: [{ type: "text", text: content }],
        };
      }
    );

    // Tool: Get repository overview
    this.server.tool(
      "get_overview",
      "Get an overview of the Commonware Library, including its purpose, design principles, and structure.",
      {},
      async () => {
        const ver = await this.getLatestVersion();
        const content = await this.fetchFile(ver, "README.md");
        if (content === null) {
          return {
            content: [{ type: "text", text: "Error fetching repository overview" }],
            isError: true,
          };
        }

        return {
          content: [{ type: "text", text: content }],
        };
      }
    );

    // Tool: List files in a crate or directory
    this.server.tool(
      "list_files",
      "List all files in a crate or directory. Useful for discovering the structure " +
        "of a crate before fetching specific files.",
      {
        crate: z
          .string()
          .optional()
          .describe(
            "Crate name (e.g., 'commonware-cryptography') or directory path. " +
              "If omitted, lists top-level directories."
          ),
        version: z.string().optional().describe("Version tag. Defaults to latest."),
      },
      async ({ crate, version }) => {
        const ver = version || (await this.getLatestVersion());
        const allFiles = await this.getFileList(ver);

        let filtered: string[];
        let prefix: string;

        if (crate) {
          // Strip commonware- prefix for folder matching
          const folderName = stripCratePrefix(crate);
          prefix = `${folderName}/`;
          filtered = allFiles.filter((f) => f.startsWith(prefix));

          if (filtered.length === 0) {
            return {
              content: [
                {
                  type: "text",
                  text: `Error: No files found for '${crate}' (version ${ver})`,
                },
              ],
              isError: true,
            };
          }
        } else {
          // List top-level directories
          prefix = "";
          const dirs = new Set<string>();
          for (const file of allFiles) {
            const topDir = file.split("/")[0];
            dirs.add(topDir);
          }
          const sortedDirs = [...dirs].sort();
          return {
            content: [
              {
                type: "text",
                text:
                  `# Top-level directories (${ver})\n\n` +
                  sortedDirs.map((d) => `- ${d}/`).join("\n"),
              },
            ],
          };
        }

        // Build tree structure
        const tree = buildFileTree(filtered, prefix);

        return {
          content: [
            {
              type: "text",
              text: `# Files in ${crate} (${ver})\n\n\`\`\`\n${tree}\n\`\`\``,
            },
          ],
        };
      }
    );
  }

  // Helper: Fetch file with Cache API caching (versioned files are immutable)
  private async fetchFile(version: string, path: string): Promise<string | null> {
    const url = `${this.env.BASE_URL}/code/${version}/${path}`;
    const cacheKey = new Request(url);
    const cache = caches.default;

    // Check cache first
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      return cachedResponse.text();
    }

    // Fetch from origin
    const response = await fetch(url);
    if (!response.ok) {
      return null;
    }

    // Cache the response (versioned files are immutable)
    const content = await response.text();
    const cacheResponse = new Response(content, {
      headers: {
        "Content-Type": "text/plain",
        "Cache-Control": `public, max-age=${FILE_CACHE_TTL}`,
      },
    });
    await cache.put(cacheKey, cacheResponse);

    return content;
  }

  // Helper: Get latest version
  private async getLatestVersion(): Promise<string> {
    const sitemap = await this.getSitemap();
    return sitemap.versions[0];
  }

  // Helper: Get all versions from sitemap
  private async getVersions(): Promise<string[]> {
    const sitemap = await this.getSitemap();
    return sitemap.versions;
  }

  // Helper: Get file list for a version
  private async getFileList(version: string): Promise<string[]> {
    const sitemap = await this.getSitemap();
    return sitemap.files[version] || [];
  }

  // Helper: Fetch sitemap.xml with Cache API caching
  private async fetchSitemap(): Promise<string> {
    const url = `${this.env.BASE_URL}/sitemap.xml`;
    const cacheKey = new Request(url);
    const cache = caches.default;

    // Check cache first
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      return cachedResponse.text();
    }

    // Fetch from origin
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("Failed to fetch sitemap");
    }

    // Cache the raw response
    const xml = await response.text();
    const cacheResponse = new Response(xml, {
      headers: {
        "Content-Type": "application/xml",
        "Cache-Control": `public, max-age=${SITEMAP_CACHE_TTL}`,
      },
    });
    await cache.put(cacheKey, cacheResponse);

    return xml;
  }

  // Helper: Get parsed sitemap data
  private async getSitemap(): Promise<SitemapData> {
    const xml = await this.fetchSitemap();
    const { versions, files } = parseSitemap(xml);

    // Convert Map to plain object
    const filesObj: Record<string, string[]> = {};
    for (const [version, paths] of files) {
      filesObj[version] = paths;
    }

    return { versions, files: filesObj };
  }

  // Helper: Get crates list (individual Cargo.toml files are cached via fetchFile)
  private async getCrates(version: string): Promise<CrateInfo[]> {
    // Fetch workspace Cargo.toml to get members
    const workspaceToml = await this.fetchFile(version, "Cargo.toml");
    if (workspaceToml === null) {
      return [];
    }

    const memberPaths = parseWorkspaceMembers(workspaceToml);
    if (memberPaths.length === 0) {
      return [];
    }

    // Fetch each crate's Cargo.toml to get description
    const cratePromises = memberPaths.map(async (path) => {
      const cargoToml = await this.fetchFile(version, `${path}/Cargo.toml`);
      if (cargoToml === null) {
        return null;
      }

      const { name, description } = parseCrateInfo(cargoToml, path);
      return { name, path, description };
    });

    const results = await Promise.all(cratePromises);
    const crates: CrateInfo[] = [];
    for (const result of results) {
      if (result) {
        crates.push(result);
      }
    }

    // Sort alphabetically by name
    crates.sort((a, b) => a.name.localeCompare(b.name));

    return crates;
  }

  // Helper: Get or build search index for a version
  private async getSearchIndex(version: string): Promise<SearchIndex> {
    const kvKey = `search-index:${version}`;

    // Check KV first
    const cached = await this.env.SEARCH_INDEX.get<SearchIndex>(kvKey, "json");
    if (cached !== null) {
      return cached;
    }

    // Build the index
    const index = await this.buildSearchIndex(version);

    // Store in KV (no expiration since versioned content is immutable)
    await this.env.SEARCH_INDEX.put(kvKey, JSON.stringify(index));

    return index;
  }

  // Helper: Build search index for a version by fetching all indexable files
  private async buildSearchIndex(version: string): Promise<SearchIndex> {
    const allFiles = await this.getFileList(version);

    // Filter to indexable file types
    const indexableFiles = allFiles.filter((file) => {
      const ext = file.split(".").pop() || "";
      return SEARCH_INDEX_EXTENSIONS.has(ext);
    });

    const index: SearchIndex = [];

    // Fetch files in batches
    for (let i = 0; i < indexableFiles.length; i += INDEX_BUILD_BATCH_SIZE) {
      const batch = indexableFiles.slice(i, i + INDEX_BUILD_BATCH_SIZE);
      const results = await Promise.all(
        batch.map(async (file) => {
          const content = await this.fetchFile(version, file);
          return content !== null ? { file, content } : null;
        })
      );

      for (const result of results) {
        if (result !== null) {
          index.push(result);
        }
      }
    }

    return index;
  }

  // Helper: Search the index for matches
  private searchIndex(
    index: SearchIndex,
    query: string,
    crate: string | undefined,
    fileType: string,
    limit: number
  ): Array<{ file: string; matches: string[] }> {
    const queryLower = query.toLowerCase();
    const results: Array<{ file: string; matches: string[] }> = [];

    for (const entry of index) {
      if (results.length >= limit) {
        break;
      }

      // Filter by crate
      if (crate) {
        const folderName = stripCratePrefix(crate);
        if (!entry.file.startsWith(`${folderName}/`)) {
          continue;
        }
      }

      // Filter by file type
      if (fileType !== "all" && !entry.file.endsWith(`.${fileType}`)) {
        continue;
      }

      // Search for matches
      const lines = entry.content.split("\n");
      const matches: string[] = [];

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        if (lines[lineNum].toLowerCase().includes(queryLower)) {
          // Include context (2 lines before and after)
          const start = Math.max(0, lineNum - 2);
          const end = Math.min(lines.length, lineNum + 3);
          const snippet = lines
            .slice(start, end)
            .map((l, idx) => `${start + idx + 1}: ${l}`)
            .join("\n");
          matches.push(snippet);

          // Limit matches per file
          if (matches.length >= 3) {
            break;
          }
        }
      }

      if (matches.length > 0) {
        results.push({ file: entry.file, matches });
      }
    }

    return results;
  }
}

// Create MCP handler using McpAgent.serve() for proper session management
const mcpHandler = McpAgent.serve("/", { binding: "MCP" });

// Worker fetch handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          name: "commonware-mcp",
          version: pkg.version,
          status: "ok",
        }),
        {
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Route to MCP agent
    return mcpHandler.fetch(request, env, ctx);
  },
};
