/**
 * Commonware MCP Server
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
 */

import { McpAgent } from "agents/mcp";
import { routeAgentRequest } from "agents";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Env } from "./env.d.ts";
import {
  getLanguage,
  isValidPath,
  parseSitemap,
  parseWorkspaceMembers,
  parseCrateInfo,
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

// Constants
const FILE_CACHE_TTL = 60 * 60 * 24 * 365; // 1 year (versioned files are immutable)
const SITEMAP_CACHE_TTL = 60 * 60; // 1 hour
const CRATES_CACHE_TTL = 60 * 60; // 1 hour
const MAX_SEARCH_RESULTS = 50;
const SEARCH_BATCH_SIZE = 10;

export class CommonwareMCP extends McpAgent<Env, {}, {}> {
  server!: McpServer;

  async init() {
    this.server = new McpServer({
      name: "commonware",
      version: pkg.version,
    });

    // Tool: Get a specific file by path
    this.server.tool(
      "get_file",
      "Retrieve a file from the Commonware repository by its path. " +
        "Paths should be relative to the repository root (e.g., 'cryptography/src/lib.rs'). " +
        "Optionally specify a version (e.g., 'v0.0.64'), defaults to latest.",
      {
        path: z
          .string()
          .describe("File path relative to repository root, e.g., 'cryptography/src/lib.rs'"),
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

        const ver = version || (await this.getLatestVersion());
        const content = await this.fetchFile(ver, path);
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
          .describe("Limit search to a specific crate (e.g., 'cryptography')"),
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
        const files = await this.getFileList(ver);

        // Filter files by crate and type
        let filtered = files;
        if (crate) {
          filtered = filtered.filter((f) => f.startsWith(`${crate}/`));
        }
        if (file_type && file_type !== "all") {
          filtered = filtered.filter((f) => f.endsWith(`.${file_type}`));
        }

        const results: Array<{ file: string; matches: string[] }> = [];
        const queryLower = query.toLowerCase();

        // Search through files (limit concurrent requests)
        for (let i = 0; i < filtered.length && results.length < limit; i += SEARCH_BATCH_SIZE) {
          const batch = filtered.slice(i, i + SEARCH_BATCH_SIZE);
          const responses = await Promise.all(
            batch.map(async (file) => {
              const content = await this.fetchFile(ver, file);
              if (content === null) {
                return null;
              }
              return { file, content };
            })
          );

          for (const resp of responses) {
            if (!resp || results.length >= limit) {
              continue;
            }

            const lines = resp.content.split("\n");
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
              results.push({ file: resp.file, matches });
            }
          }
        }

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
        crate: z.string().describe("Crate name (e.g., 'cryptography', 'consensus', 'p2p')"),
        version: z.string().optional().describe("Version tag. Defaults to latest."),
      },
      async ({ crate, version }) => {
        const ver = version || (await this.getLatestVersion());

        // Validate crate exists
        const crates = await this.getCrates(ver);
        const crateInfo = crates.find((c) => c.name === crate || c.path === crate);
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

  // Helper: Get sitemap with Cache API caching
  private async getSitemap(): Promise<SitemapData> {
    const cache = caches.default;
    const cacheKey = new Request(`${this.env.BASE_URL}/_cache/sitemap`);

    // Check cache first
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      return cachedResponse.json();
    }

    // Fetch and parse sitemap
    const response = await fetch(`${this.env.BASE_URL}/sitemap.xml`);
    if (!response.ok) {
      throw new Error("Failed to fetch sitemap");
    }

    const xml = await response.text();
    const { versions, files } = parseSitemap(xml);

    // Convert Map to plain object for JSON serialization
    const filesObj: Record<string, string[]> = {};
    for (const [version, paths] of files) {
      filesObj[version] = paths;
    }

    const sitemapData: SitemapData = { versions, files: filesObj };

    // Cache the parsed sitemap
    const cacheResponse = new Response(JSON.stringify(sitemapData), {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": `public, max-age=${SITEMAP_CACHE_TTL}`,
      },
    });
    await cache.put(cacheKey, cacheResponse);

    return sitemapData;
  }

  // Helper: Get crates list with Cache API caching
  private async getCrates(version: string): Promise<CrateInfo[]> {
    const cache = caches.default;
    const cacheKey = new Request(`${this.env.BASE_URL}/_cache/crates/${version}`);

    // Check cache first
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      return cachedResponse.json();
    }

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

    // Cache the crates list
    const cacheResponse = new Response(JSON.stringify(crates), {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": `public, max-age=${CRATES_CACHE_TTL}`,
      },
    });
    await cache.put(cacheKey, cacheResponse);

    return crates;
  }
}

// Worker fetch handler
export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
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

    // Route to MCP agent using the agents SDK helper
    // Maps requests to /agents/:agent/:name pattern for proper session handling
    return (await routeAgentRequest(request, env)) || new Response("Not found", { status: 404 });
  },
};
