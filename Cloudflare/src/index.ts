import { Container, getRandom } from "@cloudflare/containers";

interface Env {
  SCANNER: DurableObjectNamespace<ScannerContainer>;
  SCANNER__APIKEY: SecretsStoreSecret;
  CLOUDFLARE__APIKEY: SecretsStoreSecret;
  CLOUDFLARE_ACCOUNT_ID: string;
  SCANNER_R2_BUCKET: string;
  SCANNER_ENVIRONMENT: string;
}

export class ScannerContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "10m";
}

async function getStartedContainer(
  env: Env,
  apiKey: string,
  cloudflareApiKey: string,
): Promise<DurableObjectStub<ScannerContainer>> {
  const container = await getRandom(env.SCANNER, 1);

  await container.startAndWaitForPorts({
    startOptions: {
      envVars: {
        ASPNETCORE_ENVIRONMENT: env.SCANNER_ENVIRONMENT,
        Scanner__ApiKey: apiKey,
        Scanner__R2__Bucket: env.SCANNER_R2_BUCKET,
        Cloudflare__AccountId: env.CLOUDFLARE_ACCOUNT_ID,
        Cloudflare__ApiKey: cloudflareApiKey,
        Cloudflare__RequestResponseLogging: "true",
        Background__QueueLength: "100",
        Background__Log: "false",
      },
    },
  });

  return container;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      const apiKey = await env.SCANNER__APIKEY.get();
      const cloudflareApiKey = await env.CLOUDFLARE__APIKEY.get();
      const container = await getStartedContainer(env, apiKey, cloudflareApiKey);
      return container.fetch(request);
    }

    const isSynchronousScan = url.pathname === "/scan" && request.method === "POST";
    const isQueuedScan = url.pathname === "/scan/jobs" && request.method === "POST";
    const isJobQuery = url.pathname.startsWith("/scan/jobs/") && request.method === "GET";

    if (!isSynchronousScan && !isQueuedScan && !isJobQuery) {
      return new Response("Not found", { status: 404 });
    }

    const expectedKey = await env.SCANNER__APIKEY.get();
    const authorization = request.headers.get("Authorization");

    if (authorization !== `Bearer ${expectedKey}`) {
      return new Response("Unauthorized", { status: 401 });
    }

    const cloudflareApiKey = await env.CLOUDFLARE__APIKEY.get();
    const container = await getStartedContainer(env, expectedKey, cloudflareApiKey);
    return container.fetch(request);
  }
} satisfies ExportedHandler<Env>;
