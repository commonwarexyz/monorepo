# Commonware MCP

Interact with the Commonware Library via [MCP](https://modelcontextprotocol.io/) at https://mcp.commonware.xyz.

## Status

`commonware-mcp` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Tools

| Tool | Description |
|------|-------------|
| `get_file` | Retrieve a specific file by path (e.g., `commonware-cryptography/src/lib.rs`) |
| `search_code` | Search across source files for patterns or keywords |
| `list_versions` | List all available code versions |
| `list_crates` | List all crates with descriptions |
| `get_crate_readme` | Get README documentation for a specific crate |
| `get_overview` | Get the repository README/overview |
| `list_files` | List files in a crate or directory |

_Try these tools out on the [Commonware Library MCP Explorer](https://commonware.xyz/mcp)._

## Connecting

LLMs are trained on code from months ago. Web search (the default fallback for finding missing information) returns GitHub links that must be iterated file-by-file to extract relevant information (if not rate-limited first). And, the results you do find probably don't match the version you're building against.

We built our own MCP server to make LLMs building with the Commonware Library more effective. [mcp.commonware.xyz](https://mcp.commonware.xyz) provides unlimited access to a version-pinned index of all source code and documentation, along with a ranked search tool that surfaces more relevant snippets than grep (with surrounding context).

### Claude Code

```bash
claude mcp add --transport http commonware-library https://mcp.commonware.xyz
```

Or add to `.mcp.json` in your project:

```json
{
  "mcpServers": {
    "commonware-library": {
      "type": "http",
      "url": "https://mcp.commonware.xyz"
    }
  }
}
```

### Cursor

```json
{
  "mcpServers": {
    "commonware-library": {
      "url": "https://mcp.commonware.xyz"
    }
  }
}
```

## Development

### Prerequisites

- Node.js 18+
- Wrangler CLI (`npm install -g wrangler`)
- Cloudflare account

### Setup

```bash
cd mcp
npm install
```

### Local Development

```bash
# Create local D1 database and run migrations
npx wrangler d1 migrations apply commonware-mcp-search --local

# Start dev server
npm run dev
```

In a separate terminal, trigger indexing to populate the search index:

```bash
curl "http://localhost:8787/__scheduled?cron=*"
```

The server will be available at `http://localhost:8787`. Use the MCP inspector to test:

```bash
npx @modelcontextprotocol/inspector@latest
```

In the inspector UI, select **Streamable HTTP** transport, enter `http://localhost:8787` as the URL, and choose **Direct** connection mode.

### Deploy

```bash
# Login to Cloudflare (first time only)
npx wrangler login

# Create D1 database (first time only)
npx wrangler d1 create commonware-mcp-search
# Update database_id in wrangler.jsonc with the returned ID

# Run migrations (first time and after schema changes)
npx wrangler d1 migrations apply commonware-mcp-search

# Deploy
npm run deploy

# Indexing runs automatically via cron (every 10 minutes)
```

## Architecture

The server uses Cloudflare's [Agents SDK](https://developers.cloudflare.com/agents/) with the `McpAgent` class:

- **Durable Objects**: Maintains persistent connections for MCP clients
- **Sitemap-based discovery**: Parses `commonware.xyz/sitemap.xml` to discover available versions
- **D1 + FTS5**: Full-text search index powered by SQLite FTS5

## Example Usage

Once connected, you can ask your AI assistant questions like:

- "How do I use BLS signatures in commonware-cryptography?"
- "Show me the simplex consensus implementation"
- "What's the difference between the broadcast and p2p crates?"
- "Find where threshold signatures are implemented"
- "Explain how the deterministic runtime works"

The assistant will use the MCP tools to fetch actual source code rather than relying on training data.