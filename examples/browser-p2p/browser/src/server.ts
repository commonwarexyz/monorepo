import { networkInterfaces } from "node:os";
import { resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { RendezvousStore, type RendezvousPeer } from "./rendezvous-store";

interface SocketData {
  ip: string;
  session?: string;
  peer: RendezvousPeer;
}

const PORT = parsePort(Bun.env.PORT);
const DIST = fileURLToPath(new URL("../dist/", import.meta.url));
const MAX_REGISTRATION_BYTES = 256;
const store = new RendezvousStore();
const iceServers = parseIceServers(Bun.env.COMMONWARE_ICE_SERVERS);
const tls = loadTls(Bun.env.TLS_CERT_FILE, Bun.env.TLS_KEY_FILE);
const protocol = tls ? "https" : "http";
const applicationUrl = selectApplicationUrl(
  Bun.env.PUBLIC_URL,
  protocol,
  PORT,
  localIpv4Addresses(),
);

if (import.meta.main) {
  const cleanup = setInterval(() => store.cleanup(), 30_000);
  cleanup.unref();

  Bun.serve<SocketData>({
    hostname: Bun.env.HOST ?? "0.0.0.0",
    port: PORT,
    ...(tls ? { tls } : {}),
    async fetch(request, server) {
      const url = new URL(request.url);
      if (url.pathname === "/rendezvous") {
        const ip = server.requestIP(request)?.address ?? "unknown";
        const peer = new BunSocketPeer();
        if (server.upgrade(request, { data: { ip, peer } })) {
          return;
        }
        return new Response("WebSocket upgrade required", { status: 426 });
      }
      if (url.pathname === "/config.json") {
        return Response.json(
          { applicationUrl, iceServers },
          { headers: { "cache-control": "no-store" } },
        );
      }
      return serveStatic(url.pathname);
    },
    websocket: {
      open(socket) {
        (socket.data.peer as BunSocketPeer).socket = socket;
      },
      message(socket, message) {
        const text = typeof message === "string" ? message : new TextDecoder().decode(message);
        if (new TextEncoder().encode(text).byteLength > 54 * 1024) {
          socket.close(1009, "Message too large.");
          return;
        }

        let command: unknown;
        try {
          command = JSON.parse(text);
        } catch {
          socket.close(1008, "Invalid message.");
          return;
        }

        if (!socket.data.session) {
          if (text.length > MAX_REGISTRATION_BYTES || !isRegistration(command)) {
            socket.close(1008, "Invalid registration.");
            return;
          }
          if (!rateLimiter.allow(socket.data.ip)) {
            socket.close(1013, "Rate limit exceeded.");
            return;
          }
          const accepted = command.type === "create"
            ? store.create(command.session, socket.data.peer)
            : store.join(command.session, socket.data.peer);
          if (accepted) {
            socket.data.session = command.session;
          }
          return;
        }

        if (!isRelay(command)) {
          socket.close(1008, "Invalid signaling message.");
          return;
        }
        store.relay(socket.data.session, socket.data.peer, command.payload);
      },
      close(socket) {
        store.disconnect(socket.data.peer);
      },
    },
  });

  console.log(`Commonware browser chat available at ${applicationUrl}`);
}

class BunSocketPeer implements RendezvousPeer {
  socket?: Bun.ServerWebSocket<SocketData>;

  send(message: string): void {
    this.socket?.send(message);
  }

  close(code: number, reason: string): void {
    this.socket?.close(code, reason);
  }
}

class RateLimiter {
  readonly #entries = new Map<string, { start: number; count: number }>();

  constructor(private readonly limit: number, private readonly windowMs: number) {}

  allow(key: string, now = Date.now()): boolean {
    const entry = this.#entries.get(key);
    if (!entry || entry.start + this.windowMs <= now) {
      this.#entries.set(key, { start: now, count: 1 });
      return true;
    }
    entry.count += 1;
    return entry.count <= this.limit;
  }
}

const rateLimiter = new RateLimiter(30, 60_000);

async function serveStatic(pathname: string): Promise<Response> {
  const path = resolveStaticPath(DIST, pathname);
  if (!path) {
    return new Response("Not found", { status: 404 });
  }
  const file = Bun.file(path);
  if (!(await file.exists())) {
    return new Response("Not found", { status: 404 });
  }
  return new Response(file, {
    headers: {
      "cache-control": cacheControl(pathname),
      "x-content-type-options": "nosniff",
    },
  });
}

export function cacheControl(pathname: string): string {
  if (pathname === "/" || pathname.startsWith("/wasm/")) {
    return "no-store";
  }
  return "public, max-age=31536000, immutable";
}

export function resolveStaticPath(root: string, pathname: string): string | undefined {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return undefined;
  }
  const relative = decoded === "/" ? "index.html" : decoded.replace(/^\/+/, "");
  const normalizedRoot = resolve(root);
  const path = resolve(normalizedRoot, relative);
  if (path !== normalizedRoot && !path.startsWith(normalizedRoot + sep)) {
    return undefined;
  }
  return path;
}

export function selectApplicationUrl(
  configured: string | undefined,
  protocol: "http" | "https",
  port: number,
  addresses: readonly string[],
): string {
  if (configured) {
    return validateApplicationUrl(configured).toString();
  }

  const address = addresses.find((candidate) => !isLoopback(candidate));
  return new URL(`${protocol}://${address ?? "localhost"}:${port}/`).toString();
}

function validateApplicationUrl(value: string): URL {
  if (value.length > 2048) {
    throw new Error("PUBLIC_URL is too long.");
  }

  const url = new URL(value);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("PUBLIC_URL must use http or https.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("PUBLIC_URL must not contain credentials, a query, or a fragment.");
  }
  return url;
}

function localIpv4Addresses(): string[] {
  return Object.values(networkInterfaces())
    .flatMap((addresses) => addresses ?? [])
    .filter((address) => address.family === "IPv4" && !address.internal)
    .map((address) => address.address);
}

function isLoopback(address: string): boolean {
  return address === "localhost" || address.startsWith("127.");
}

function loadTls(certFile: string | undefined, keyFile: string | undefined) {
  if (!certFile && !keyFile) {
    return undefined;
  }
  if (!certFile || !keyFile) {
    throw new Error("TLS_CERT_FILE and TLS_KEY_FILE must be set together.");
  }
  return {
    cert: Bun.file(certFile),
    key: Bun.file(keyFile),
  };
}

function isRegistration(value: unknown): value is { type: "create" | "join"; session: string } {
  return isRecord(value) &&
    Object.keys(value).length === 2 &&
    (value.type === "create" || value.type === "join") &&
    typeof value.session === "string";
}

function isRelay(value: unknown): value is { type: "signal"; payload: string } {
  return isRecord(value) &&
    Object.keys(value).length === 2 &&
    value.type === "signal" &&
    typeof value.payload === "string";
}

export function parseIceServers(raw: string | undefined): RTCIceServer[] {
  if (!raw) {
    return [{ urls: "stun:stun.cloudflare.com:3478" }];
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("COMMONWARE_ICE_SERVERS must be valid JSON.");
  }
  if (!Array.isArray(value) || value.length > 8) {
    throw new Error("COMMONWARE_ICE_SERVERS must contain at most eight entries.");
  }
  const encoded = JSON.stringify(value);
  if (encoded.length > 8192) {
    throw new Error("COMMONWARE_ICE_SERVERS is too large.");
  }
  return value as RTCIceServer[];
}

function parsePort(raw: string | undefined): number {
  const port = raw === undefined ? 3000 : Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("PORT must be a valid TCP port.");
  }
  return port;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
