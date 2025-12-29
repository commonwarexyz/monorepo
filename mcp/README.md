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

## Connecting

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

### Cloudflare AI Playground

Visit [playground.ai.cloudflare.com](https://playground.ai.cloudflare.com) and connect to `https://mcp.commonware.xyz`.

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
npm run dev
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

# Deploy
npm run deploy
```

## Architecture

The server uses Cloudflare's [Agents SDK](https://developers.cloudflare.com/agents/) with the `McpAgent` class:

- **Durable Objects**: Maintains persistent connections for MCP clients
- **Sitemap-based discovery**: Parses `commonware.xyz/sitemap.xml` to discover available files
- **Caching**: Files cached indefinitely (immutable); sitemap cached for 1 hour

### Endpoints

- `/` - MCP server (Streamable HTTP transport)
- `/health` - Health check (JSON status)

## Example Usage

Once connected, you can ask your AI assistant questions like:

- "How do I use BLS signatures in commonware-cryptography?"
- "Show me the simplex consensus implementation"
- "What's the difference between the broadcast and p2p crates?"
- "Find where threshold signatures are implemented"
- "Explain how the deterministic runtime works"

The assistant will use the MCP tools to fetch actual source code rather than relying on training data.