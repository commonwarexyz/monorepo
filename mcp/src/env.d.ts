/// <reference types="@cloudflare/workers-types" />

export interface Env {
  MCP: DurableObjectNamespace;
  SEARCH_DB: D1Database;
  BASE_URL: string;
}

declare module "cloudflare:workers" {
  interface CloudflareBindings extends Env {}
}
