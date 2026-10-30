# Soenneker.Cloudflare.Clamav

A native-AOT ClamAV scanning container with a durable Cloudflare Worker API. The container supervises ClamAV and FreshClam; the Worker coordinates private R2 uploads, D1 job records, and retryable Queues delivery.

## Scan guarantees

- `clean` means ClamAV completed inspection under the configured policy with no detection. Antivirus scanning is one security control, not a guarantee that a file is harmless.
- `infected` identifies a detected signature. `inconclusive` identifies encrypted content, archive limits, or broken formats flagged by the engine. `error` identifies an engine failure. Only `clean` sets `clean: true`.
- Results include a scan ID, SHA-256, byte count, engine version, loaded signature version/date, and elapsed time. The Worker verifies results against the persisted upload checksum and size.
- Limits cover HTTP bytes, aggregate upload reservations, concurrent scans, upload duration, scan duration, expanded archive bytes, nested files, and recursion.
- Readiness requires a responding daemon and loaded signatures no more than three days old. Startup seeds the writable database from packaged definitions, refreshes it with FreshClam, and starts the daemon. Updates drain active scans and restart the daemon to confirm the loaded database. Update failures retain usable signatures; stale signatures prevent scanning.
- Durable submission returns `202` only after upload and job persistence. Delivery is at least once; leases and conditional completion prevent an obsolete attempt from overwriting a newer one. No in-memory queue or container-local upload is required for recovery.

## Deploy the Worker

The reusable deployment is in `worker/`. It requires a private R2 bucket, D1 database, scan queue, dead-letter queue, and a scanner API key of at least 32 characters. Container instances receive only the scanner key, not account-wide Cloudflare credentials. Cloudflare request/response operation logging remains enabled.

From `worker/`:

```sh
npm ci
npx wrangler r2 bucket create scanner-uploads
npx wrangler d1 create scanner-jobs
npx wrangler queues create scanner-scans
npx wrangler queues create scanner-scans-dead
npx wrangler secret put SCANNER_API_KEY
```

Set the returned database ID in `wrangler.jsonc`, and configure a route/custom domain. `workers_dev` is disabled by default. Use separate bindings, queues, databases, and secrets for each environment. Keep the R2 bucket private: do not enable public access or attach a public custom domain.

```sh
npm run migrate
npm run typecheck
npm test
npm run deploy
```

The checked-in deployment builds `../Dockerfile`. For releases, replace the image with `docker.io/soenneker/cloudflare-clamav@sha256:<verified-digest>`. Verify the image signature and provenance before promotion. The deployment defaults to one 4-GiB container and two queue consumers; job state supports multiple container instances, but routing and `max_instances` must be increased together when scaling.

## HTTP API

Use `Authorization: Bearer <SCANNER_API_KEY>` for all routes except `/health`. Upload raw `application/octet-stream` bytes, not multipart form data. Responses are never cacheable.

| Method | Route | Behavior |
| --- | --- | --- |
| GET | `/health` | HTTP host liveness; does not assert scanner readiness |
| GET | `/ready` | Authenticated daemon and signature readiness; 503 while unavailable |
| POST | `/scan` | Synchronous verdict; 429 when admission is full, 503 while unavailable |
| POST | `/scan/jobs` | Durable submission through the Worker; 202 with a relative polling URL |
| GET | `/scan/jobs/{id}` | Durable job state and result through the Worker |

A standalone container serves liveness, readiness, and synchronous scans. Its job routes return 501 and direct callers to the Worker.

```sh
curl --fail-with-body https://YOUR_SCANNER/scan \
  -H "Authorization: Bearer $SCANNER_API_KEY" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @document.pdf
```

For a background job, supply `Content-Length`, `Idempotency-Key` (1–128 printable ASCII characters), and `X-Content-SHA256` (64 lowercase hexadecimal characters). Calculate the checksum over the exact uploaded bytes. R2 validates it before acceptance. Reusing a key with different checksum or size returns 409; retrying an accepted submission returns its existing job ID and current status. Retain the same key across network retries.

```sh
checksum=$(sha256sum document.pdf | cut -d ' ' -f 1)
curl --fail-with-body https://YOUR_SCANNER/scan/jobs \
  -H "Authorization: Bearer $SCANNER_API_KEY" \
  -H "Content-Type: application/octet-stream" \
  -H "Idempotency-Key: YOUR_UNIQUE_SUBMISSION_ID" \
  -H "X-Content-SHA256: $checksum" \
  --data-binary @document.pdf
```

Poll the returned `statusUrl` until `completed` or `failed`. A completed job can be infected or inconclusive: inspect `result.verdict` and `result.clean`. Honor `Retry-After` on admission failures and polling responses. The generated .NET client can supply these headers through its request configuration callback.

## Durability, capacity, and retention

D1 reserves admission atomically before upload: at most eight uploads, 100 unfinished jobs, and 10 GiB of retained payloads. An upload has a two-minute deadline. Background jobs have a 24-hour lifetime, at most three processing attempts, and a twelve-minute processing lease. Only the active lease holder may commit a result. A one-minute scheduled sweep redispatches ready work, recovers expired leases, fails exhausted jobs, and retries payload cleanup. Duplicate queue delivery is expected and safe.

Terminal payloads are deleted promptly, and terminal job records/idempotency keys expire seven days after completion. Interrupted uploads expire after ten minutes. Configure an R2 lifecycle rule expiring payload objects after two days as a final cleanup backstop; this is longer than the maximum job lifetime. Keep Cron Triggers enabled. Investigate dead-letter messages and `recovery`/`scan_attempt_failed` events rather than treating a dead-letter queue as completed work.

The Worker schema is created by versioned D1 migrations. Apply migrations before deploying a new Worker. No import from older snapshot-based storage is performed. Roll back the Worker and container by verified image digest only to a schema-compatible version.

## Run the container locally

```sh
docker build --platform linux/amd64 -t soenneker-cloudflare-clamav:test .
docker run --rm -p 127.0.0.1:8080:8080 \
  -e Scanner__ApiKey="$SCANNER_API_KEY" \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --memory=4g --cpus=2 \
  --tmpfs /data:rw,noexec,nosuid,size=2g,uid=1654,gid=1654 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  soenneker-cloudflare-clamav:test
```

The image runs as UID 1654. `/data` holds writable definitions, configuration, scan scratch space, and temporary uploads. Application binaries remain read-only. Allow outbound access to the official ClamAV definition service. A persistent `/data` volume can reduce cold-start downloads; never share it between running containers. The packaged native binaries support Linux amd64; the source host also supports Windows x64 for development.

| Container setting | Default |
| --- | --- |
| `Scanner__MaximumFileSize` | 104857600 bytes (100 MiB maximum) |
| `Scanner__MaximumConcurrentScans` | 2 |
| `Scanner__TemporaryByteBudget` | 268435456 bytes of upload reservations |
| `Scanner__UploadTimeout` | `00:02:00` |
| `Scanner__ScanTimeout` | `00:05:00` |
| `Scanner__MaximumExpandedSize` | 268435456 bytes per scan |
| `Scanner__MaximumArchiveFiles` | 10000 |
| `Scanner__MaximumRecursion` | 16 |
| `Scanner__DefinitionUpdateInterval` | `01:00:00` |
| `Scanner__MaximumDefinitionAge` | `3.00:00:00` |

The upload reservation budget excludes database memory and archive extraction scratch space; size the container memory and writable filesystem for all three. Settings are validated. The Worker verifies freshness within three days, so increasing the container threshold does not relax durable-job policy.

## Observability and verification

Structured logs include scan IDs, verdict/reason, sizes, durations, attempts, queue age, recovery, update failures, and Cloudflare operation request/response metadata. They do not include raw uploaded file bytes. Keep Cloudflare request/response logging enabled in all environments.

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces and metrics using standard OpenTelemetry settings. The meter `Soenneker.Cloudflare.Clamav` emits scan outcomes, latency, active reservations, reserved bytes, admission rejections, definition-update failures, readiness, and loaded signature age. A signature-age value of -1 means the loaded version is not known. Alert on sustained readiness loss, age approaching three days, oldest queued age, failed attempts, admission saturation, and dead-letter queue growth. Worker logs provide queue/recovery metrics; configure Cloudflare alerts for queue backlog, dead-letter messages, and Cron Trigger failures.

```sh
dotnet test --project test/Soenneker.Cloudflare.Clamav.Tests
dotnet build src/Soenneker.Cloudflare.Clamav -p:OpenApiGenerateDocuments=true
npm --prefix worker run typecheck
npm --prefix worker test
python -m pip install -r scripts/requirements-test.txt
python scripts/container-smoke.py soenneker-cloudflare-clamav:test
# Linux/macOS with Docker and Node:
python scripts/worker-smoke.py
```

OpenAPI generation uses the real route metadata without starting native scanner processes. The contract is written to `artifacts/openapi/openapi.json`. CI tests real local D1/R2 behavior and the final image with clean/EICAR files, encrypted/nested archives, upload limits, cleanup, and daemon recovery. Image publication requires these checks, high/critical vulnerability gates, an SBOM, a keyless signature, and build provenance before promoting release tags. Vulnerability scanners do not establish the absence of vulnerabilities in native bundled binaries; keep the ClamAV distribution packages and pinned base images current.
