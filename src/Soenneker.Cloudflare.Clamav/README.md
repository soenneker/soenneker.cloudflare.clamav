# Soenneker.Cloudflare.Clamav

A ClamAV HTTP scanning service for Cloudflare Workers, Containers, and R2. The Worker authenticates requests and starts a container on demand. R2 stores asynchronous job status and results; uploads are temporary files in the container.

## Build and run

The image currently supports Linux amd64. From the repository root:

```sh
docker build --platform linux/amd64 -t soenneker-cloudflare-clamav .
docker run --rm -p 8080:8080 --env-file scanner.env soenneker-cloudflare-clamav
```

Supply your own values in `scanner.env` (do not commit it):

```dotenv
Scanner__ApiKey=YOUR_SCANNER_API_KEY
Scanner__R2__Bucket=YOUR_R2_BUCKET
Cloudflare__AccountId=YOUR_CLOUDFLARE_ACCOUNT_ID
Cloudflare__ApiKey=YOUR_CLOUDFLARE_API_TOKEN
```

Create the R2 bucket first and provide a Cloudflare API token with access to its objects. R2 configuration is required for both synchronous and queued scans. `Cloudflare:RequestResponseLogging` remains enabled. `Scanner__MaximumFileSize` overrides the default 100 MiB upload limit.

ClamAV binaries and definitions are provided by `Soenneker.Clamav.Util` and its dependencies. Scans update definitions and have a ten-minute scan timeout. The container needs network access for R2 and definition updates, plus writable temporary and ClamAV working directories.

## HTTP API

- `GET /health`: ClamAV version readiness check.
- `POST /scan`: raw file bytes; returns `clean`, `threat`, and `engine`.
- `POST /scan/jobs`: raw file bytes; returns HTTP 202 with `id`, `status`, and `statusUrl`.
- `GET /scan/jobs/{id}`: persisted job status and result.

All scan and job requests require `Authorization: Bearer YOUR_SCANNER_API_KEY`.

```sh
curl --fail-with-body http://localhost:8080/scan \
  -H "Authorization: Bearer $SCANNER_API_KEY" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @file-to-scan
```

The work queue and uploaded files are local to the running container. R2 persists job records, but queued work does not survive container termination and is not automatically retried.

## Cloudflare deployment

From `Cloudflare`, install dependencies with `npm ci` and run `npm run typecheck`. Copy `wrangler.jsonc` to `wrangler.local.jsonc`, replace the account and Secrets Store placeholders, and set your bucket and deployment name. The two Secrets Store entries are `SCANNER__APIKEY` and `CLOUDFLARE__APIKEY`.

Deploy with Docker running and Cloudflare credentials configured:

```sh
npm run deploy -- --config wrangler.local.jsonc
```

The default configuration exposes a workers.dev endpoint, keeps one container instance, and sleeps after ten minutes of inactivity. Custom domains, account IDs, and environment-specific resources belong in the consumer's deployment configuration.

## Image releases

The `publish-image` workflow builds and pushes Linux amd64 images to `ghcr.io/soenneker/soenneker.cloudflare.clamav`. A manual run publishes `sha-<commit>`; a pushed `v*` tag also publishes that tag. The GHCR package must be made public after its first publication to allow anonymous pulls.
