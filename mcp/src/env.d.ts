/// <reference types="@cloudflare/workers-types" />

export interface Env {
  MCP_OBJECT: DurableObjectNamespace;
  BASE_URL: string;
  CACHE?: KVNamespace;
}

declare module "cloudflare:workers" {
  interface CloudflareBindings extends Env {}
}
