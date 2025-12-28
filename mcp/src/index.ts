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
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Env } from "./env.d.ts";

// Cached data structures
interface SitemapCache {
  versions: string[];
  files: Map<string, string[]>; // version -> file paths
  timestamp: number;
}

interface CrateInfo {
  name: string;
  path: string;
  description: string;
}

interface CratesCache {
  crates: CrateInfo[];
  timestamp: number;
}

export class CommonwareMCP extends McpAgent<Env, {}, {}> {
  server = new McpServer({
    name: "commonware",
    version: "0.0.1",
  });

  private sitemapCache: SitemapCache | null = null;
  private cratesCache: CratesCache | null = null;
  private readonly CACHE_TTL = 60 * 60 * 1000; // 1 hour

  async init() {
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
        const ver = version || (await this.getLatestVersion());
        const url = `${this.env.BASE_URL}/code/${ver}/${path}`;

        const response = await fetch(url);
        if (!response.ok) {
          return {
            content: [
              {
                type: "text",
                text: `Error: File not found at ${path} (version ${ver}). Status: ${response.status}`,
              },
            ],
            isError: true,
          };
        }

        const content = await response.text();
        return {
          content: [
            {
              type: "text",
              text: `# ${path} (${ver})\n\n\`\`\`${this.getLanguage(path)}\n${content}\n\`\`\``,
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
          .describe("Maximum number of results to return (default: 10)"),
      },
      async ({ query, crate, file_type, version, max_results }) => {
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
        const batchSize = 5;
        for (let i = 0; i < filtered.length && results.length < max_results; i += batchSize) {
          const batch = filtered.slice(i, i + batchSize);
          const responses = await Promise.all(
            batch.map(async (file) => {
              const url = `${this.env.BASE_URL}/code/${ver}/${file}`;
              try {
                const resp = await fetch(url);
                if (!resp.ok) return null;
                const content = await resp.text();
                return { file, content };
              } catch {
                return null;
              }
            })
          );

          for (const resp of responses) {
            if (!resp || results.length >= max_results) continue;

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
                if (matches.length >= 3) break;
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
              `## ${r.file}\n\n\`\`\`${this.getLanguage(r.file)}\n${r.matches.join("\n---\n")}\n\`\`\``
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

        const url = `${this.env.BASE_URL}/code/${ver}/${crateInfo.path}/README.md`;
        const response = await fetch(url);
        if (!response.ok) {
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

        const content = await response.text();
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
        const url = `${this.env.BASE_URL}/code/${ver}/README.md`;

        const response = await fetch(url);
        if (!response.ok) {
          return {
            content: [{ type: "text", text: "Error fetching repository overview" }],
            isError: true,
          };
        }

        const content = await response.text();
        return {
          content: [{ type: "text", text: content }],
        };
      }
    );
  }

  // Helper: Get latest version
  private async getLatestVersion(): Promise<string> {
    const versions = await this.getVersions();
    return versions[0];
  }

  // Helper: Get all versions from sitemap
  private async getVersions(): Promise<string[]> {
    await this.refreshSitemapCache();
    return this.sitemapCache!.versions;
  }

  // Helper: Get file list for a version
  private async getFileList(version: string): Promise<string[]> {
    await this.refreshSitemapCache();
    return this.sitemapCache!.files.get(version) || [];
  }

  // Helper: Get crates list with descriptions
  private async getCrates(version: string): Promise<CrateInfo[]> {
    // Check cache (keyed by version in a simple way - just check if latest)
    if (this.cratesCache && Date.now() - this.cratesCache.timestamp < this.CACHE_TTL) {
      return this.cratesCache.crates;
    }

    const crates: CrateInfo[] = [];

    // Fetch workspace Cargo.toml to get members
    const workspaceUrl = `${this.env.BASE_URL}/code/${version}/Cargo.toml`;
    const workspaceResp = await fetch(workspaceUrl);
    if (!workspaceResp.ok) {
      return [];
    }

    const workspaceToml = await workspaceResp.text();

    // Parse members from workspace Cargo.toml
    // Format: members = [\n    "crate1",\n    "crate2",\n    ...]
    const membersMatch = workspaceToml.match(/members\s*=\s*\[([\s\S]*?)\]/);
    if (!membersMatch) {
      return [];
    }

    const membersBlock = membersMatch[1];
    const memberPaths: string[] = [];

    // Extract quoted strings from members array
    const pathMatches = membersBlock.matchAll(/"([^"]+)"/g);
    for (const match of pathMatches) {
      const path = match[1];
      // Filter out examples and fuzz targets - only include top-level crates
      if (!path.includes("/")) {
        memberPaths.push(path);
      }
    }

    // Fetch each crate's Cargo.toml to get description
    const cratePromises = memberPaths.map(async (path) => {
      const cargoUrl = `${this.env.BASE_URL}/code/${version}/${path}/Cargo.toml`;
      try {
        const resp = await fetch(cargoUrl);
        if (!resp.ok) return null;

        const cargoToml = await resp.text();

        // Extract package name
        const nameMatch = cargoToml.match(/name\s*=\s*"([^"]+)"/);
        const name = nameMatch ? nameMatch[1].replace("commonware-", "") : path;

        // Extract description
        const descMatch = cargoToml.match(/description\s*=\s*"([^"]+)"/);
        const description = descMatch ? descMatch[1] : "No description available";

        return { name, path, description };
      } catch {
        return null;
      }
    });

    const results = await Promise.all(cratePromises);
    for (const result of results) {
      if (result) {
        crates.push(result);
      }
    }

    // Sort alphabetically by name
    crates.sort((a, b) => a.name.localeCompare(b.name));

    this.cratesCache = {
      crates,
      timestamp: Date.now(),
    };

    return crates;
  }

  // Helper: Refresh sitemap cache
  private async refreshSitemapCache(): Promise<void> {
    if (this.sitemapCache && Date.now() - this.sitemapCache.timestamp < this.CACHE_TTL) {
      return;
    }

    const response = await fetch(`${this.env.BASE_URL}/sitemap.xml`);
    if (!response.ok) {
      throw new Error("Failed to fetch sitemap");
    }

    const xml = await response.text();
    const versions: string[] = [];
    const files = new Map<string, string[]>();

    // Parse sitemap XML (simple regex-based parsing)
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

    // Sort versions (newest first)
    versions.sort((a, b) => {
      const partsA = a.slice(1).split(".").map(Number);
      const partsB = b.slice(1).split(".").map(Number);
      for (let i = 0; i < 3; i++) {
        if (partsA[i] !== partsB[i]) return partsB[i] - partsA[i];
      }
      return 0;
    });

    this.sitemapCache = {
      versions,
      files,
      timestamp: Date.now(),
    };
  }

  // Helper: Get file language for syntax highlighting
  private getLanguage(path: string): string {
    if (path.endsWith(".rs")) return "rust";
    if (path.endsWith(".toml")) return "toml";
    if (path.endsWith(".md")) return "markdown";
    return "";
  }
}

// Worker fetch handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === "/" || url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          name: "commonware-mcp",
          version: "0.0.1",
          status: "ok",
          endpoints: {
            sse: "/sse",
            mcp: "/mcp",
          },
        }),
        {
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Route to MCP agent for SSE and MCP endpoints
    if (url.pathname === "/sse" || url.pathname === "/mcp") {
      // Get or create durable object instance
      const id = env.MCP_OBJECT.idFromName("singleton");
      const stub = env.MCP_OBJECT.get(id);
      return stub.fetch(request);
    }

    return new Response("Not Found", { status: 404 });
  },
};
