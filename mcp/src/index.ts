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
  buildSnippets,
  formatSnippet,
  formatWithLineNumbers,
  getLanguage,
  isValidPath,
  parseSitemap,
  parseWorkspaceMembers,
  parseCrateInfo,
  selectTopSnippets,
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
const INDEX_BUILD_BATCH_SIZE = 20; // D1 has 100 bind param limit, 20 rows × 3 cols = 60

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
        "Optionally specify a version (e.g., 'v0.0.64'), defaults to latest. " +
        "Optionally specify start_line and end_line to fetch a specific range (0-indexed, inclusive). " +
        "Line numbers in output match those returned by search_code.",
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
        start_line: z
          .number()
          .int()
          .min(0)
          .optional()
          .describe("Start line number (0-indexed, inclusive). Defaults to beginning of file."),
        end_line: z
          .number()
          .int()
          .min(0)
          .optional()
          .describe("End line number (0-indexed, inclusive). Defaults to end of file."),
      },
      async ({ path, version, start_line, end_line }) => {
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

        // Format with line numbers (and optionally filter to range)
        const formatted = formatWithLineNumbers(content, start_line, end_line);

        // Build header with line range info if specified
        const totalLines = content.split("\n").length;
        const rangeInfo =
          start_line !== undefined || end_line !== undefined
            ? ` [lines ${start_line ?? 0}-${end_line ?? totalLines - 1}]`
            : "";

        return {
          content: [
            {
              type: "text",
              text: `# ${path} (${ver})${rangeInfo}\n\n\`\`\`${getLanguage(path)}\n${formatted}\n\`\`\``,
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
        query: z.string().describe("Search query"),
        mode: z
          .enum(["substring", "word"])
          .optional()
          .default("substring")
          .describe(
            "Search mode: 'substring' for literal substring match (min 3 chars), " +
              "'word' for word-based search with prefix matching"
          ),
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
      async ({ query, mode, crate, file_type, version, max_results }) => {
        // Substring mode requires at least 3 characters (trigram tokenizer)
        if (mode === "substring" && query.trim().length < 3) {
          return {
            content: [
              {
                type: "text",
                text: `Error: Substring search requires at least 3 characters`,
              },
            ],
            isError: true,
          };
        }

        // Clamp max_results to valid range (negative LIMIT in SQLite means no limit)
        const limit = Math.max(1, Math.min(max_results, MAX_SEARCH_RESULTS));

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
        const results = await this.searchWithFTS(ver, query, mode, crate, file_type, limit);

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
              text: `# Search results for "${query}" (${ver})\n\nFound ${results.length} file(s):\n\n${output}\n\n---\nFiles are listed by path. Use \`list_crates\` to see crate name to path mappings. Use \`get_file\` with \`start_line\` and \`end_line\` to fetch specific line ranges instead of entire files.`,
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
        if (versions.length === 0) {
          return {
            content: [{ type: "text", text: "No versions available" }],
            isError: true,
          };
        }
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

        const output = crates
          .map((c) => `- **${c.name}** (${c.path}): ${c.description}`)
          .join("\n");

        return {
          content: [
            {
              type: "text",
              text: `# Commonware Crates (${ver})\n\n${output}\n\nUse \`get_crate_readme\` to get detailed documentation for any crate. Use the path in parentheses with \`list_files\` or \`get_file\` to browse crate contents.`,
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
        const cratePath = await this.resolveCratePath(ver, crate);
        const content = await this.fetchFile(ver, `${cratePath}/README.md`);
        if (content === null) {
          return {
            content: [
              {
                type: "text",
                text: `Error: README not found for crate '${crate}' (version ${ver}). Use \`list_crates\` to see available crates.`,
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
          // Resolve crate name or path to actual directory
          const folderName = await this.resolveCratePath(ver, crate);
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
    const result = await this.env.SEARCH_DB.withSession()
      .prepare("SELECT version FROM versions")
      .all<{ version: string }>();

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
    const result = await this.env.SEARCH_DB.withSession()
      .prepare("SELECT path FROM files WHERE version = ?")
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
    const result = await this.env.SEARCH_DB.withSession()
      .prepare("SELECT 1 FROM versions WHERE version = ?")
      .bind(version)
      .first();
    return result !== null;
  }

  // Helper: Resolve crate name or path to actual directory path
  private async resolveCratePath(version: string, crate: string): Promise<string> {
    // Try matching by crate name first (e.g., "commonware-consensus-fuzz" -> "consensus/fuzz")
    const crates = await this.getCrates(version);
    const byName = crates.find((c) => c.name === crate);
    if (byName) {
      return byName.path;
    }

    // Otherwise strip prefix and use as path (e.g., "commonware-cryptography" -> "cryptography")
    return stripCratePrefix(crate);
  }

  // Helper: Search using D1 FTS5
  private async searchWithFTS(
    version: string,
    query: string,
    mode: "substring" | "word",
    crate: string | undefined,
    fileType: string,
    limit: number
  ): Promise<Array<{ file: string; matches: string[] }>> {
    // Build FTS query based on mode
    const { ftsQuery, snippetMatcher } = this.buildFTSQuery(query, mode);
    if (ftsQuery === null) {
      return [];
    }

    // Select FTS table based on mode
    const ftsTable = mode === "substring" ? "files_fts_substring" : "files_fts_word";

    // Build the SQL query with filters
    let sql = `
      SELECT f.path, f.content
      FROM ${ftsTable}
      JOIN files f ON ${ftsTable}.rowid = f.id
      WHERE ${ftsTable} MATCH ?
        AND f.version = ?
    `;
    const params: (string | number)[] = [ftsQuery, version];

    // Add crate filter (escape LIKE wildcards)
    if (crate) {
      const folderName = await this.resolveCratePath(version, crate);
      const escaped = folderName.replace(/[%_\\]/g, "\\$&");
      sql += " AND f.path LIKE ? ESCAPE '\\'";
      params.push(`${escaped}/%`);
    }

    // Add file type filter (escape LIKE wildcards)
    if (fileType !== "all") {
      const escaped = fileType.replace(/[%_\\]/g, "\\$&");
      sql += " AND f.path LIKE ? ESCAPE '\\'";
      params.push(`%.${escaped}`);
    }

    // Order by relevance and limit
    sql += ` ORDER BY bm25(${ftsTable}) LIMIT ?`;
    params.push(limit);

    // Execute the SQL query
    const results = await this.env.SEARCH_DB.withSession()
      .prepare(sql)
      .bind(...params)
      .all<{ path: string; content: string }>();

    // Extract snippets with context
    const output: Array<{ file: string; matches: string[] }> = [];

    for (const row of results.results) {
      const lines = row.content.split("\n");

      // Score each line by number of matching terms
      const lineScores = lines.map((line) => snippetMatcher(line.toLowerCase()));

      // Build and select top non-overlapping snippets
      const snippets = buildSnippets(lineScores);
      const selected = selectTopSnippets(snippets, 5);

      // Format selected snippets
      const matches = selected.map(({ start, end }) => formatSnippet(lines, start, end));

      // Always include file if FTS5 matched it
      output.push({ file: row.path, matches });
    }

    return output;
  }

  // Helper: Build FTS5 query based on mode
  // Returns a snippetMatcher that scores lines (0 = no match, higher = more matches)
  private buildFTSQuery(
    query: string,
    mode: "substring" | "word"
  ): { ftsQuery: string | null; snippetMatcher: (line: string) => number } {
    const trimmed = query.trim();

    if (mode === "substring") {
      // Trigram requires at least 3 characters
      if (trimmed.length < 3) {
        return { ftsQuery: null, snippetMatcher: () => 0 };
      }
      // Escape double quotes for FTS5
      const escaped = trimmed.replace(/"/g, '""');
      const queryLower = trimmed.toLowerCase();
      return {
        ftsQuery: `"${escaped}"`,
        // Substring mode: count occurrences
        snippetMatcher: (line) => {
          let count = 0;
          let idx = 0;
          while ((idx = line.indexOf(queryLower, idx)) !== -1) {
            count++;
            idx += queryLower.length;
          }
          return count;
        },
      };
    } else {
      // Word mode: escape special chars and add prefix matching
      const escaped = trimmed.replace(/["()*:^-]/g, " ").trim();
      const words = escaped.split(/\s+/).filter((w) => w.length > 0);
      if (words.length === 0) {
        return { ftsQuery: null, snippetMatcher: () => 0 };
      }
      const ftsQuery = words.map((w) => `${w}*`).join(" ");
      const wordsLower = words.map((w) => w.toLowerCase());
      return {
        ftsQuery,
        // Word mode: count total occurrences of all query words
        snippetMatcher: (line) => {
          let count = 0;
          for (const word of wordsLower) {
            let idx = 0;
            while ((idx = line.indexOf(word, idx)) !== -1) {
              count++;
              idx += word.length;
            }
          }
          return count;
        },
      };
    }
  }
}

// Create MCP handler using McpAgent.serve() for proper session management
// CORS is handled automatically by the WorkerTransport with permissive defaults
const mcpHandler = McpAgent.serve("/", { binding: "MCP" });

// Helper: Sync indexed versions with sitemap (index one version per run to avoid timeout)
async function reindexVersions(
  env: Env
): Promise<{ indexed: string | null; pruned: string | null }> {
  // Fetch sitemap to get available versions
  const sitemapUrl = `${env.BASE_URL}/sitemap.xml`;
  const response = await fetch(sitemapUrl);
  if (!response.ok) {
    throw new Error("Failed to fetch sitemap");
  }
  const xml = await response.text();
  const { versions: sitemapVersions, files } = parseSitemap(xml);
  const sitemapSet = new Set(sitemapVersions);

  // Get already indexed versions (use primary for writes)
  const session = env.SEARCH_DB.withSession("first-primary");
  const indexedResult = await session.prepare("SELECT version FROM versions").all<{
    version: string;
  }>();
  const indexedSet = new Set(indexedResult.results.map((r) => r.version));

  // Prune ONE version not in sitemap (delete version record first to prevent
  // queries from finding a version with no files)
  let pruned: string | null = null;
  for (const oldVersion of indexedSet) {
    if (!sitemapSet.has(oldVersion)) {
      await session.batch([
        session.prepare("DELETE FROM versions WHERE version = ?").bind(oldVersion),
        session.prepare("DELETE FROM files WHERE version = ?").bind(oldVersion),
      ]);
      pruned = oldVersion;
      break;
    }
  }

  // Index ONE version not yet indexed (newest first since sitemapVersions is sorted desc)
  let indexed: string | null = null;
  for (const version of sitemapVersions) {
    if (indexedSet.has(version)) {
      continue;
    }

    // Get all files for this version
    const versionFiles = files.get(version) || [];

    // Fetch and index all files in batches
    for (let i = 0; i < versionFiles.length; i += INDEX_BUILD_BATCH_SIZE) {
      const batch = versionFiles.slice(i, i + INDEX_BUILD_BATCH_SIZE);
      const results = await Promise.all(
        batch.map(async (file) => {
          const fileUrl = `${env.BASE_URL}/code/${version}/${file}`;
          const res = await fetch(fileUrl);
          if (!res.ok) {
            throw new Error(`Failed to fetch ${file} for ${version}: ${res.status}`);
          }
          const content = await res.text();
          return { file, content };
        })
      );

      // Use multi-row INSERT for better performance
      const placeholders = results.map(() => "(?, ?, ?)").join(", ");
      const params = results.flatMap((r) => [version, r.file, r.content]);
      await session
        .prepare(`INSERT OR REPLACE INTO files (version, path, content) VALUES ${placeholders}`)
        .bind(...params)
        .run();
    }

    // Mark version as indexed
    await session
      .prepare("INSERT OR REPLACE INTO versions (version) VALUES (?)")
      .bind(version)
      .run();
    indexed = version;
    break;
  }

  return { indexed, pruned };
}

// Worker fetch handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Test endpoint: synchronous reindex
    if (url.pathname === "/__test/reindex") {
      try {
        const result = await reindexVersions(env);
        return new Response(JSON.stringify(result), {
          headers: { "Content-Type": "application/json" },
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: String(error) }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    // Route all requests to MCP agent (handles CORS including OPTIONS preflight)
    return mcpHandler.fetch(request, env, ctx);
  },

  // Scheduled handler for automatic indexing
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(reindexVersions(env));
  },
};
