/**
 * Commonware MCP Server
 *
 * A Model Context Protocol server for the Commonware Library that exposes
 * source code and documentation to AI assistants like Claude, Cursor, etc.
 *
 * Tools:
 * - get_file: Retrieve a specific file by path
 * - search_code: Search across source code files
 * - list_versions: List available code versions
 * - list_crates: List all crates in the workspace
 * - get_crate_readme: Get the README for a specific crate
 * - get_blog_post: Get a technical blog post by slug
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Env } from "./env.d.ts";

// Cached sitemap data structure
interface SitemapCache {
  versions: string[];
  files: Map<string, string[]>; // version -> file paths
  blogPosts: string[];
  timestamp: number;
}

// Known crates in the workspace (from Cargo.toml)
const CRATES = [
  "broadcast",
  "codec",
  "coding",
  "collector",
  "conformance",
  "consensus",
  "cryptography",
  "deployer",
  "macros",
  "math",
  "p2p",
  "pipeline",
  "resolver",
  "runtime",
  "storage",
  "stream",
  "utils",
] as const;

type CrateName = (typeof CRATES)[number];

export class CommonwareMCP extends McpAgent<Env, {}, {}> {
  server = new McpServer({
    name: "commonware",
    version: "0.0.1",
  });

  private sitemapCache: SitemapCache | null = null;
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
          .map((r) => `## ${r.file}\n\n\`\`\`${this.getLanguage(r.file)}\n${r.matches.join("\n---\n")}\n\`\`\``)
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

    // Tool: List crates
    this.server.tool(
      "list_crates",
      "List all crates (primitives) in the Commonware workspace with their descriptions.",
      {},
      async () => {
        const descriptions: Record<CrateName, string> = {
          broadcast: "Disseminate data over a wide-area network",
          codec: "Serialize structured data",
          coding: "Encode data for recovery from a subset of fragments (Reed-Solomon/ZODA)",
          collector: "Collect responses to committable requests",
          conformance: "Assert stability of encoding and mechanisms over time",
          consensus: "Order opaque messages in a Byzantine environment",
          cryptography: "Generate keys, sign messages, verify signatures (BLS, Ed25519)",
          deployer: "Deploy infrastructure across cloud providers",
          macros: "Procedural macros for the workspace",
          math: "Mathematical objects and operations",
          p2p: "Communicate with authenticated peers over encrypted connections",
          pipeline: "Mechanisms under development",
          resolver: "Resolve data identified by a fixed-length key",
          runtime: "Execute asynchronous tasks with configurable scheduler",
          storage: "Persist and retrieve data from an abstract store",
          stream: "Exchange messages over arbitrary transport",
          utils: "Common utilities shared across crates",
        };

        const output = CRATES.map((c) => `- **${c}**: ${descriptions[c]}`).join("\n");

        return {
          content: [
            {
              type: "text",
              text: `# Commonware Crates\n\n${output}\n\nUse \`get_crate_readme\` to get detailed documentation for any crate.`,
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
          .enum(CRATES)
          .describe("Crate name (e.g., 'cryptography', 'consensus', 'p2p')"),
        version: z.string().optional().describe("Version tag. Defaults to latest."),
      },
      async ({ crate, version }) => {
        const ver = version || (await this.getLatestVersion());
        const url = `${this.env.BASE_URL}/code/${ver}/${crate}/README.md`;

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

    // Tool: Get blog post
    this.server.tool(
      "get_blog_post",
      "Get a technical blog post from the Commonware documentation. " +
        "Blog posts contain deep dives into design decisions and implementation details.",
      {
        slug: z
          .string()
          .describe(
            "Blog post slug (e.g., 'zoda', 'mmr', 'threshold-simplex', 'commonware-runtime')"
          ),
      },
      async ({ slug }) => {
        // Try both .md and direct fetch
        const url = `${this.env.BASE_URL}/blogs/${slug}`;

        const response = await fetch(url);
        if (!response.ok) {
          return {
            content: [
              {
                type: "text",
                text: `Error: Blog post '${slug}' not found. Available posts include: ` +
                  "zoda, mmr, minimmit, adb-current, adb-any, buffered-signatures, " +
                  "conformance, introducing-commonware, commonware-the-anti-framework, " +
                  "commonware-runtime, commonware-cryptography, commonware-broadcast, " +
                  "commonware-deployer, reshare, threshold-simplex, qmdb, only-time-will-tell",
              },
            ],
            isError: true,
          };
        }

        // The response is HTML, extract text content
        const html = await response.text();
        // Simple HTML to text extraction for blog content
        const text = this.htmlToText(html);

        return {
          content: [{ type: "text", text }],
        };
      }
    );

    // Tool: List blog posts
    this.server.tool(
      "list_blog_posts",
      "List all available technical blog posts from Commonware documentation.",
      {},
      async () => {
        const posts = [
          { slug: "introducing-commonware", title: "Introducing Commonware" },
          { slug: "commonware-the-anti-framework", title: "The Anti-Framework Philosophy" },
          { slug: "commonware-runtime", title: "Abstract Runtime Design" },
          { slug: "commonware-cryptography", title: "Cryptographic Primitives" },
          { slug: "commonware-broadcast", title: "Reliable Broadcast Protocol" },
          { slug: "commonware-deployer", title: "Infrastructure Deployment" },
          { slug: "zoda", title: "Fast Block Dissemination with ZODA" },
          { slug: "mmr", title: "Merkle Mountain Range Implementation" },
          { slug: "minimmit", title: "Minimal Commit Protocol" },
          { slug: "adb-current", title: "Authenticated Data Broadcast (Current)" },
          { slug: "adb-any", title: "Authenticated Data Broadcast (Any)" },
          { slug: "buffered-signatures", title: "Efficient Signature Aggregation" },
          { slug: "conformance", title: "Format Stability Testing" },
          { slug: "reshare", title: "Threshold Secret Resharing" },
          { slug: "threshold-simplex", title: "Threshold Consensus Mechanism" },
          { slug: "qmdb", title: "Query-able Merkle Database" },
          { slug: "only-time-will-tell", title: "Time and Consensus" },
        ];

        const output = posts.map((p) => `- **${p.slug}**: ${p.title}`).join("\n");

        return {
          content: [
            {
              type: "text",
              text: `# Commonware Blog Posts\n\n${output}\n\nUse \`get_blog_post\` with a slug to read a specific post.`,
            },
          ],
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
    const blogPosts: string[] = [];

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

      // Extract blog posts
      const blogMatch = url.match(/\/blogs\/([^/]+)$/);
      if (blogMatch) {
        blogPosts.push(blogMatch[1]);
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
      blogPosts,
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

  // Helper: Extract text from HTML
  private htmlToText(html: string): string {
    // Remove script and style elements
    let text = html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "");
    text = text.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "");

    // Extract main content (between article tags if present)
    const articleMatch = text.match(/<article[^>]*>([\s\S]*?)<\/article>/i);
    if (articleMatch) {
      text = articleMatch[1];
    } else {
      // Try main tag
      const mainMatch = text.match(/<main[^>]*>([\s\S]*?)<\/main>/i);
      if (mainMatch) {
        text = mainMatch[1];
      }
    }

    // Convert headers
    text = text.replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, "\n# $1\n");
    text = text.replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, "\n## $1\n");
    text = text.replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, "\n### $1\n");
    text = text.replace(/<h4[^>]*>([\s\S]*?)<\/h4>/gi, "\n#### $1\n");

    // Convert code blocks
    text = text.replace(/<pre[^>]*><code[^>]*>([\s\S]*?)<\/code><\/pre>/gi, "\n```\n$1\n```\n");
    text = text.replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, "`$1`");

    // Convert paragraphs and line breaks
    text = text.replace(/<p[^>]*>([\s\S]*?)<\/p>/gi, "\n$1\n");
    text = text.replace(/<br\s*\/?>/gi, "\n");

    // Convert lists
    text = text.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, "- $1\n");

    // Convert links
    text = text.replace(/<a[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi, "[$2]($1)");

    // Remove remaining HTML tags
    text = text.replace(/<[^>]+>/g, "");

    // Decode HTML entities
    text = text.replace(/&lt;/g, "<");
    text = text.replace(/&gt;/g, ">");
    text = text.replace(/&amp;/g, "&");
    text = text.replace(/&quot;/g, '"');
    text = text.replace(/&#39;/g, "'");
    text = text.replace(/&nbsp;/g, " ");

    // Clean up whitespace
    text = text.replace(/\n\s*\n\s*\n/g, "\n\n");
    text = text.trim();

    return text;
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
