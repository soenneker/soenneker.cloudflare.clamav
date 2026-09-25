# Soenneker.Cloudflare.Clamav

**ClamAV file scanning for your applications, packaged as a Docker container and ready to run behind a Cloudflare Worker.**

Scan uploads, attachments, and documents through a simple HTTP API hosted in your own Cloudflare account. Configure four values, deploy the container, and start submitting files. Choose synchronous scan results or background jobs with status and results stored in R2.

For .NET applications, pair the scanner with [Soenneker.Cloudflare.Clamav.OpenApiClientUtil](https://github.com/soenneker/soenneker.cloudflare.clamav.openapiclientutil). It provides a cached, typed OpenAPI client with dependency injection and bearer authentication configured for you.

[Docker Hub](https://hub.docker.com/r/soenneker/cloudflare-clamav) · [.NET client utility on NuGet](https://www.nuget.org/packages/Soenneker.Cloudflare.Clamav.OpenApiClientUtil/) · [OpenAPI specification](https://github.com/soenneker/soenneker.cloudflare.clamav.openapi)

## Why use it?

- **Deploy the image.** Run ClamAV on Cloudflare Containers or locally without installing the scanner on your application server.
- **Keep integration simple.** Send file bytes over HTTP or use the typed .NET client.
- **Choose your scan flow.** Wait for a verdict or submit a background job and poll for its result.
- **Definition updates built in.** The first scan initializes definitions through `Soenneker.Clamav.Util`, and a background service refreshes them hourly for long-running containers.
- **Run in your own account.** Your Cloudflare deployment hosts the scanner and its R2 job records.

## How it works

```text
Your application / .NET OpenAPI client
                 |
                 v
        Cloudflare Worker
                 |
                 v
    Docker container running ClamAV
                 |
                 v
      R2: job status and results
```

The Worker forwards requests to the container, which validates the scanner bearer token and scans uploaded bytes. Files are written to temporary storage and deleted after processing. R2 stores background job records, not uploaded files.

## Deploy on Cloudflare

You need a Cloudflare account with Containers enabled, an R2 bucket, and a Cloudflare API token with permission to read and write that bucket's objects through the Cloudflare API. R2 configuration is required for both synchronous and background scans.

### 1. Create your Worker

Start with the [Cloudflare Containers template](https://developers.cloudflare.com/containers/get-started/). Choose a project directory such as `clamav-worker` and skip its initial deployment so you can configure the scanner first:

```sh
npm create cloudflare@latest -- --template=cloudflare/templates/containers-template
cd clamav-worker
```

This repository supplies the scanner image. The Worker examples below belong in your own deployment project.

### 2. Set the image and configuration

Replace the new project's `wrangler.jsonc` with this configuration, supplying your account ID and bucket name:

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "clamav-worker",
  "main": "src/index.ts",
  "compatibility_date": "2026-09-22",
  "workers_dev": true,
  "account_id": "YOUR_CLOUDFLARE_ACCOUNT_ID",
  "vars": {
    "CLOUDFLARE_ACCOUNT_ID": "YOUR_CLOUDFLARE_ACCOUNT_ID",
    "SCANNER_R2_BUCKET": "YOUR_R2_BUCKET"
  },
  "containers": [{
    "class_name": "ClamavContainer",
    "image": "docker.io/soenneker/cloudflare-clamav:latest",
    "instance_type": "standard-1",
    "max_instances": 1
  }],
  "durable_objects": {
    "bindings": [{ "name": "CLAMAV", "class_name": "ClamavContainer" }]
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["ClamavContainer"] }]
}
```

Cloudflare supports [public Docker Hub images directly](https://developers.cloudflare.com/containers/guides/image-management/), so you do not need to build the scanner to use a published image. Pin a published version or digest for repeatable deployments.

Store the two sensitive values as Worker secrets:

```sh
npx wrangler secret put SCANNER_API_KEY
npx wrangler secret put CLOUDFLARE_API_TOKEN
```

Choose a strong scanner API key and use that same value in your calling application. The Cloudflare API token is a separate credential used by the container to access R2.

| Worker setting | Container environment variable | Purpose |
| --- | --- | --- |
| `SCANNER_API_KEY` (secret) | `Scanner__ApiKey` | Authenticates scan and job requests |
| `SCANNER_R2_BUCKET` | `Librarian__R2__BucketName` | R2 bucket for job records |
| `CLOUDFLARE_ACCOUNT_ID` | `Librarian__R2__AccountId` | Account containing the R2 bucket |
| `CLOUDFLARE_API_TOKEN` (secret) | `Cloudflare__ApiKey` | Cloudflare API access for R2 |

### 3. Connect the Worker to the container

Replace `src/index.ts` in your Worker project:

```typescript
import { Container, getContainer } from "@cloudflare/containers";

interface Env {
  CLAMAV: DurableObjectNamespace<ClamavContainer>;
  SCANNER_API_KEY: string;
  SCANNER_R2_BUCKET: string;
  CLOUDFLARE_ACCOUNT_ID: string;
  CLOUDFLARE_API_TOKEN: string;
}

export class ClamavContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "30m";
  enableInternet = true;

  envVars = {
    Scanner__ApiKey: this.env.SCANNER_API_KEY,
    Librarian__R2__BucketName: this.env.SCANNER_R2_BUCKET,
    Librarian__R2__AccountId: this.env.CLOUDFLARE_ACCOUNT_ID,
    Cloudflare__ApiKey: this.env.CLOUDFLARE_API_TOKEN,
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return getContainer(env.CLAMAV, "scanner").fetch(request);
  },
};
```

Worker variables and secrets must be [passed into the container through `envVars`](https://developers.cloudflare.com/containers/examples/env-vars-and-secrets/). Double underscores in the container variable names map to .NET configuration sections.

This example routes requests to one named instance. Its 30-minute idle sleep setting is a starting point; account for background queue duration when choosing lifecycle settings.

### 4. Deploy and scan

```sh
npx wrangler deploy
```

Allow time for initial container provisioning, then use the Worker URL printed by Wrangler. Set `SCANNER_API_KEY` in your shell to the secret you created:

```sh
curl --fail-with-body https://clamav-worker.YOUR_SUBDOMAIN.workers.dev/scan \
  -H "Authorization: Bearer $SCANNER_API_KEY" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @file-to-scan
```

A clean scan returns:

```json
{ "clean": true, "threat": null, "engine": "ClamAV" }
```

## Use it from .NET

[Soenneker.Cloudflare.Clamav.OpenApiClientUtil](https://github.com/soenneker/soenneker.cloudflare.clamav.openapiclientutil) handles client creation, caching, and bearer authentication so your application can focus on the scan result.

```sh
dotnet add package Soenneker.Cloudflare.Clamav.OpenApiClientUtil
```

Configure your application's endpoint in `appsettings.json`:

```json
{
  "Scanner": {
    "BaseUrl": "https://clamav-worker.YOUR_SUBDOMAIN.workers.dev/"
  }
}
```

Supply `Scanner:ApiKey` through your application's secret configuration, or set the environment variable `Scanner__ApiKey`. Use the same scanner key configured in the Worker; your application does not need the container's Cloudflare API token.

Register the utility with dependency injection:

```csharp
using Soenneker.Cloudflare.Clamav.OpenApiClientUtil.Registrars;

builder.Services.AddCloudflareClamavOpenApiClientUtilAsSingleton();
```

Inject `ICloudflareClamavOpenApiClientUtil` and scan a file:

```csharp
using Soenneker.Cloudflare.Clamav.OpenApiClientUtil.Abstract;

public sealed class UploadScanner(ICloudflareClamavOpenApiClientUtil clientUtil)
{
    public async Task<bool> IsClean(Stream file, CancellationToken cancellationToken = default)
    {
        var client = await clientUtil.Get(cancellationToken);
        var result = await client.Scan.PostAsync(file, cancellationToken: cancellationToken);
        return result?.Clean == true;
    }
}
```

For background scans, submit the stream and retrieve the job on subsequent polls:

```csharp
var client = await clientUtil.Get(cancellationToken);
var accepted = await client.Scan.Jobs.PostAsync(file, cancellationToken: cancellationToken);

if (accepted?.Id is not { } jobId)
    throw new InvalidOperationException("The scanner did not return a job ID.");

var job = await client.Scan.Jobs[jobId].GetAsync(cancellationToken: cancellationToken);
// Poll until status is "completed" or "failed"; read Result after completion.
```

## HTTP API

Upload raw file bytes with `Content-Type: application/octet-stream`, rather than multipart form data. All scan and job endpoints require `Authorization: Bearer YOUR_SCANNER_API_KEY`.

| Method | Route | Response |
| --- | --- | --- |
| `GET` | `/health` | ClamAV version readiness check; no authentication required |
| `POST` | `/scan` | Scan verdict with `clean`, `threat`, and `engine` |
| `POST` | `/scan/jobs` | HTTP 202 with `id`, `status`, and `statusUrl` |
| `GET` | `/scan/jobs/{id}` | Persisted job status and result |

Job states are `queued`, `processing`, `completed`, and `failed`. A completed job means scanning finished; inspect its result to determine whether the file was clean.

The [OpenAPI 3.1 document](https://raw.githubusercontent.com/soenneker/soenneker.cloudflare.clamav.openapi/main/openapi.json) describes the API for client generation and integrations.

## Run locally with Docker

Create a local `scanner.env` file and keep it out of source control:

```dotenv
Scanner__ApiKey=YOUR_SCANNER_API_KEY
Librarian__R2__BucketName=YOUR_R2_BUCKET
Librarian__R2__AccountId=YOUR_CLOUDFLARE_ACCOUNT_ID
Cloudflare__ApiKey=YOUR_CLOUDFLARE_API_TOKEN
```

Run the Linux amd64 image:

```sh
docker run --rm --platform linux/amd64 -p 8080:8080 \
  --env-file scanner.env soenneker/cloudflare-clamav:latest
```

Use `http://localhost:8080/` as your client's `Scanner:BaseUrl`, or send the same curl request to `http://localhost:8080/scan`. Local execution still requires the R2 configuration above.

To build the image yourself, run this from the repository root and substitute the resulting image name in `docker run`:

```sh
docker build --platform linux/amd64 -t soenneker-cloudflare-clamav .
```

## Runtime details

- The default upload limit is **100 MiB**. Set `Scanner__MaximumFileSize` in the container environment to override it in bytes; upstream request limits still apply.
- Each ClamAV scan has a **10-minute timeout**. Use background jobs when waiting on a single HTTP request is unsuitable.
- The container needs outbound network access for R2 and definition updates, plus writable temporary and ClamAV working directories. First requests may take longer while the container starts and definitions initialize.
- Definition refreshes run on a `PeriodicTimer`, starting one interval after application startup. The default interval is one hour; override `Scanner:DefinitionUpdateInterval` with a positive `TimeSpan`, for example container environment variable `Scanner__DefinitionUpdateInterval=02:00:00` for two hours. Updates run sequentially, failures are logged and retried on the next tick, and shutdown cancels the updater.
- The running ClamAV daemon checks local database files every ten minutes and reloads changed definitions. This check does not download definitions, so newly downloaded signatures may take up to that check interval, plus reload time, to become active. Engine upgrades require an updated container image and redeployment.
- Job records use a single Librarian R2 snapshot at `scanner/jobs.json`; override it with `Librarian__R2__ObjectKey`. Only one scanner instance may own each snapshot. Every job update persists the complete snapshot before returning. Legacy `scanner/jobs/{id}.json` objects are not imported automatically.
- **Background jobs are not a durable queue.** R2 preserves job records, but uploads and pending work remain inside the container. Container termination loses unfinished work, with no automatic retry; its persisted status can remain queued or processing.
- `/health` checks ClamAV version availability. It does not verify R2 access or definition freshness.

## OpenAPI generation

Generate the contract locally from controller routes, response types, and XML documentation without starting a webserver or configuring Cloudflare credentials:

```sh
dotnet build src/Soenneker.Cloudflare.Clamav/Soenneker.Cloudflare.Clamav.csproj --configuration Release -p:OpenApiGenerateDocuments=true
```

The output is `artifacts/openapi/openapi.json`. The `publish-openapi` workflow publishes contract changes to [soenneker.cloudflare.clamav.openapi](https://github.com/soenneker/soenneker.cloudflare.clamav.openapi).
