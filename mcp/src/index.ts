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
  sortVersionsDesc,
  stripCratePrefix,
} from "./utils.ts";
import pkg from "../package.json";

// Types
interface CrateInfo {
  name: string;
  path: string;
  description: string;
}

// Constants
const MAX_SEARCH_RESULTS = 50;
const INDEX_BUILD_BATCH_SIZE = 50;

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
        query: z.string().describe("Search query (matches words with prefix matching)"),
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

        // Check if version exists
        const isIndexed = await this.isVersionIndexed(ver);
        if (!isIndexed) {
          return {
            content: [
              {
                type: "text",
                text: `Error: Version '${ver}' not found`,
              },
            ],
            isError: true,
          };
        }

        // Search using D1 FTS5
        const results = await this.searchWithFTS(ver, query, crate, file_type, limit);

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

  // Helper: Fetch file from commonware.xyz
  private async fetchFile(version: string, path: string): Promise<string | null> {
    const url = `${this.env.BASE_URL}/code/${version}/${path}`;
    const response = await fetch(url);
    if (!response.ok) {
      return null;
    }
    return response.text();
  }

  // Helper: Get indexed versions from D1 (sorted descending)
  private async getIndexedVersions(): Promise<string[]> {
    const result = await this.env.SEARCH_DB.prepare("SELECT version FROM indexed_versions").all<{
      version: string;
    }>();

    const versions = result.results.map((r) => r.version);
    sortVersionsDesc(versions);
    return versions;
  }

  // Helper: Get latest version
  private async getLatestVersion(): Promise<string> {
    const versions = await this.getIndexedVersions();
    if (versions.length === 0) {
      throw new Error("No versions available");
    }
    return versions[0];
  }

  // Helper: Get all versions
  private async getVersions(): Promise<string[]> {
    return this.getIndexedVersions();
  }

  // Helper: Get file list for a version (from D1)
  private async getFileList(version: string): Promise<string[]> {
    const result = await this.env.SEARCH_DB.prepare("SELECT path FROM files WHERE version = ?")
      .bind(version)
      .all<{ path: string }>();

    return result.results.map((r) => r.path);
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

  // Helper: Check if a version has been indexed
  private async isVersionIndexed(version: string): Promise<boolean> {
    const result = await this.env.SEARCH_DB.prepare(
      "SELECT 1 FROM indexed_versions WHERE version = ?"
    )
      .bind(version)
      .first();
    return result !== null;
  }

  // Helper: Search using D1 FTS5
  private async searchWithFTS(
    version: string,
    query: string,
    crate: string | undefined,
    fileType: string,
    limit: number
  ): Promise<Array<{ file: string; matches: string[] }>> {
    // Escape special FTS5 characters and add prefix matching
    const ftsQuery = this.buildFTSQuery(query);

    // Handle queries with no valid search terms
    if (ftsQuery === null) {
      return [];
    }

    // Build the SQL query with filters
    let sql = `
      SELECT f.path, f.content
      FROM files_fts
      JOIN files f ON files_fts.rowid = f.id
      WHERE files_fts MATCH ?
        AND f.version = ?
    `;
    const params: (string | number)[] = [ftsQuery, version];

    // Add crate filter
    if (crate) {
      const folderName = stripCratePrefix(crate);
      sql += " AND f.path LIKE ?";
      params.push(`${folderName}/%`);
    }

    // Add file type filter
    if (fileType !== "all") {
      sql += " AND f.path LIKE ?";
      params.push(`%.${fileType}`);
    }

    // Order by relevance and limit
    sql += " ORDER BY bm25(files_fts) LIMIT ?";
    params.push(limit);

    const results = await this.env.SEARCH_DB.prepare(sql)
      .bind(...params)
      .all<{ path: string; content: string }>();

    // Extract snippets with context
    // Match any word from the query (matching FTS5 behavior)
    const queryWords = query
      .toLowerCase()
      .split(/\s+/)
      .filter((w) => w.length > 0);
    const output: Array<{ file: string; matches: string[] }> = [];

    for (const row of results.results) {
      const lines = row.content.split("\n");
      const matches: string[] = [];

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const lineLower = lines[lineNum].toLowerCase();
        // Check if any query word appears in this line
        if (queryWords.some((word) => lineLower.includes(word))) {
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

      // Always include file if FTS5 matched it
      output.push({ file: row.path, matches });
    }

    return output;
  }

  // Helper: Build FTS5 query with prefix matching
  // Returns null if query has no valid search terms
  private buildFTSQuery(query: string): string | null {
    // Escape special FTS5 characters: " ( ) * : ^
    const escaped = query.replace(/["()*:^]/g, " ").trim();

    // Split into words and add prefix matching to each
    const words = escaped.split(/\s+/).filter((w) => w.length > 0);

    if (words.length === 0) {
      return null;
    }

    // Use prefix matching for each word
    return words.map((w) => `"${w}"*`).join(" ");
  }
}

// Create MCP handler using McpAgent.serve() for proper session management
const mcpHandler = McpAgent.serve("/", { binding: "MCP" });

// Helper: Sync indexed versions with sitemap (index new, prune removed)
async function reindexVersions(env: Env): Promise<{ indexed: string[]; pruned: string[] }> {
  // Fetch sitemap to get available versions
  const sitemapUrl = `${env.BASE_URL}/sitemap.xml`;
  const response = await fetch(sitemapUrl);
  if (!response.ok) {
    throw new Error("Failed to fetch sitemap");
  }
  const xml = await response.text();
  const { versions: sitemapVersions, files } = parseSitemap(xml);
  const sitemapSet = new Set(sitemapVersions);

  // Get already indexed versions
  const indexedResult = await env.SEARCH_DB.prepare("SELECT version FROM indexed_versions").all<{
    version: string;
  }>();
  const indexedSet = new Set(indexedResult.results.map((r) => r.version));

  // Index versions in sitemap that aren't indexed yet
  const indexed: string[] = [];
  for (const version of sitemapVersions) {
    if (indexedSet.has(version)) {
      continue;
    }

    // Get all files for this version
    const versionFiles = files.get(version) || [];

    // Fetch and index all files in batches
    let filesIndexed = 0;
    for (let i = 0; i < versionFiles.length; i += INDEX_BUILD_BATCH_SIZE) {
      const batch = versionFiles.slice(i, i + INDEX_BUILD_BATCH_SIZE);
      const results = await Promise.all(
        batch.map(async (file) => {
          const fileUrl = `${env.BASE_URL}/code/${version}/${file}`;
          const res = await fetch(fileUrl);
          if (!res.ok) {
            return null;
          }
          const content = await res.text();
          return { file, content };
        })
      );

      const successfulResults = results.filter((r) => r !== null);
      const statements = successfulResults.map((r) =>
        env.SEARCH_DB.prepare(
          "INSERT OR REPLACE INTO files (version, path, content) VALUES (?, ?, ?)"
        ).bind(version, r.file, r.content)
      );

      if (statements.length > 0) {
        await env.SEARCH_DB.batch(statements);
        filesIndexed += statements.length;
      }
    }

    // Only mark as indexed if at least one file was successfully indexed
    if (filesIndexed > 0) {
      await env.SEARCH_DB.prepare("INSERT OR REPLACE INTO indexed_versions (version) VALUES (?)")
        .bind(version)
        .run();
      indexed.push(version);
    }
  }

  // Prune versions not in sitemap
  const pruned: string[] = [];
  for (const oldVersion of indexedSet) {
    if (!sitemapSet.has(oldVersion)) {
      await env.SEARCH_DB.prepare("DELETE FROM files WHERE version = ?").bind(oldVersion).run();
      await env.SEARCH_DB.prepare("DELETE FROM indexed_versions WHERE version = ?")
        .bind(oldVersion)
        .run();
      pruned.push(oldVersion);
    }
  }

  return { indexed, pruned };
}

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

  // Scheduled handler for automatic indexing
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(reindexVersions(env));
  },
};
