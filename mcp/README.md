# Commonware MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io/) server for the Commonware Library, deployed on Cloudflare Workers. This server exposes Commonware source code to AI assistants like Claude, Cursor, and other MCP-compatible clients.

## Tools

| Tool | Description |
|------|-------------|
| `get_file` | Retrieve a specific file by path (e.g., `cryptography/src/lib.rs`) |
| `search_code` | Search across source files for patterns or keywords |
| `list_versions` | List all available code versions |
| `list_crates` | List all crates with descriptions |
| `get_crate_readme` | Get README documentation for a specific crate |
| `get_overview` | Get the repository README/overview |

## Connecting

### Claude Desktop (via mcp-remote)

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "commonware": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://commonware-mcp.<your-account>.workers.dev/sse"
      ]
    }
  }
}
```

### Cursor

Add to your Cursor MCP settings:

```json
{
  "mcpServers": {
    "commonware": {
      "url": "https://commonware-mcp.<your-account>.workers.dev/mcp"
    }
  }
}
```

### Cloudflare AI Playground

Visit [ai.cloudflare.com](https://ai.cloudflare.com) and connect to your deployed worker URL.

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
npx @modelcontextprotocol/inspector@latest http://localhost:8787/sse
```

### Deploy

```bash
# Login to Cloudflare (first time only)
npx wrangler login

# Deploy
npm run deploy
```

## Architecture

The server uses Cloudflare's [Agents SDK](https://developers.cloudflare.com/agents/) with the `McpAgent` class:

- **Durable Objects**: Maintains persistent SSE connections for MCP clients
- **Sitemap-based discovery**: Parses `commonware.xyz/sitemap.xml` to discover available files
- **Caching**: Sitemap data is cached for 1 hour to reduce upstream requests

### Endpoints

- `/` - Health check (JSON status)
- `/sse` - SSE transport for MCP connections (legacy)
- `/mcp` - Streamable HTTP transport (recommended)

## Example Usage

Once connected, you can ask your AI assistant questions like:

- "How do I use BLS signatures in commonware-cryptography?"
- "Show me the simplex consensus implementation"
- "What's the difference between the broadcast and p2p crates?"
- "Find where threshold signatures are implemented"
- "Explain how the deterministic runtime works"

The assistant will use the MCP tools to fetch actual source code rather than relying on training data.

## License

Apache-2.0 OR MIT (same as Commonware Library)
