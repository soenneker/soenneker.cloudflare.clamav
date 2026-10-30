import { Container, getContainer } from "@cloudflare/containers";
import { query } from "./storage";
import type { Env } from "./types";
import { lookup, problem, processJob, recover, submit } from "./jobs";

export class ScannerContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "15m";
  envVars = { Scanner__ApiKey: this.env.SCANNER_API_KEY, Scanner__WorkingDirectory: "/data", Cloudflare__RequestResponseLogging: "true" };
}

async function authorized(request: Request, env: Env): Promise<boolean> {
  if (!env.SCANNER_API_KEY || env.SCANNER_API_KEY.length < 32) throw new Error("SCANNER_API_KEY must contain at least 32 characters.");
  const encoder = new TextEncoder();
  const supplied = await crypto.subtle.digest("SHA-256", encoder.encode(request.headers.get("Authorization") ?? ""));
  const expected = await crypto.subtle.digest("SHA-256", encoder.encode(`Bearer ${env.SCANNER_API_KEY}`));
  return crypto.subtle.timingSafeEqual(supplied, expected);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const path = new URL(request.url).pathname;
      if (path === "/health" && request.method === "GET") return Response.json({ ready: true }, { headers: { "Cache-Control": "no-store" } });
      if (!await authorized(request, env)) return problem(401, "Unauthorized.");
      if (path === "/scan/jobs" && request.method === "POST") return await submit(request, env);
      if (path.startsWith("/scan/jobs/") && request.method === "GET") return await lookup(env, path.slice(11));
      if ((path === "/scan" && request.method === "POST") || (path === "/ready" && request.method === "GET")) {
        if (path === "/ready") {
          await query(env, "SELECT 1");
          console.log(JSON.stringify({ provider: "Cloudflare", request: { operation: "R2.head", key: "readiness" } }));
          const object = await env.UPLOADS.head("readiness");
          console.log(JSON.stringify({ provider: "Cloudflare", response: { operation: "R2.head", exists: object !== null } }));
        }
        const response = await getContainer(env.SCANNER, "scanner").fetch(request);
        const headers = new Headers(response.headers); headers.set("Cache-Control", "no-store");
        return new Response(response.body, { status: response.status, headers });
      }
      return problem(404, "Not found.");
    } catch (error) {
      console.error(JSON.stringify({ event: "request_failed", error: String(error) }));
      return problem(503, "Scanner service is temporarily unavailable.", 10);
    }
  },
  async queue(batch: MessageBatch<{ id: string }>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        if (await processJob(env, message.body.id)) message.ack();
        else message.retry({ delaySeconds: 60 });
      } catch (error) {
        console.error(JSON.stringify({ event: "delivery_failed", id: message.body.id, error: String(error) }));
        message.retry({ delaySeconds: 60 });
      }
    }
  },
  async scheduled(_event: ScheduledController, env: Env): Promise<void> { await recover(env); },
} satisfies ExportedHandler<Env, { id: string }>;
