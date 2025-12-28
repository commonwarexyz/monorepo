/// <reference types="@cloudflare/workers-types" />

export interface Env {
  CommonwareMCP: DurableObjectNamespace;
  BASE_URL: string;
}

declare module "cloudflare:workers" {
  interface CloudflareBindings extends Env {}
}
