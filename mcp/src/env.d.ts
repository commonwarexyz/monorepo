/// <reference types="@cloudflare/workers-types" />

export interface Env {
  MCP: DurableObjectNamespace;
  BASE_URL: string;
}

declare module "cloudflare:workers" {
  interface CloudflareBindings extends Env {}
}
