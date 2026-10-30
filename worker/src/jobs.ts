import { getContainer } from "@cloudflare/containers";
import type { Env, Job, Verdict } from "./types";
import { deleteUpload, getJob, jobResponse, query } from "./storage";

export function problem(status: number, title: string, retryAfter?: number): Response {
  return Response.json({ title, status }, { status, headers: { "Content-Type": "application/problem+json", "Cache-Control": "no-store",
    ...(retryAfter ? { "Retry-After": String(retryAfter) } : {}) } });
}

export async function submit(request: Request, env: Env): Promise<Response> {
  const key = request.headers.get("Idempotency-Key");
  const sha = request.headers.get("X-Content-SHA256")?.toLowerCase();
  const declared = request.headers.get("Content-Length");
  if (!key || key.length > 128 || !/^[\x21-\x7e]+$/.test(key) || !sha || !/^[a-f0-9]{64}$/.test(sha))
    return problem(400, "Supply Idempotency-Key (1–128 ASCII characters) and X-Content-SHA256.");
  if (declared === null || !/^\d+$/.test(declared)) return problem(411, "Supply Content-Length.");
  const size = Number(declared);
  if (!Number.isSafeInteger(size) || size > 104857600) return problem(413, "The maximum scan size is 100 MiB.");
  const keyHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key))), b => b.toString(16).padStart(2, "0")).join("");
  const id = crypto.randomUUID();
  // A single atomic statement reserves both job count and aggregate storage before accepting bytes.
  await query(env, `INSERT INTO jobs (id, idempotency_key, sha256, size, status)
    SELECT ?, ?, ?, ?, 'uploading' WHERE
      (SELECT COUNT(*) FROM jobs WHERE status IN ('uploading','queued','processing')) < 100
      AND (SELECT COUNT(*) FROM jobs WHERE status = 'uploading') < 8
      AND COALESCE((SELECT SUM(size) FROM jobs WHERE blob_deleted = 0),0) + ? <= 10737418240
    ON CONFLICT(idempotency_key) DO NOTHING`, [id, keyHash, sha, size, size]);
  const job = (await query<Job>(env, "SELECT * FROM jobs WHERE idempotency_key = ?", [keyHash])).results[0];
  if (!job) return problem(429, "Job capacity is reserved. Retry later.", 30);
  if (job.sha256 !== sha || job.size !== size) return problem(409, "The idempotency key belongs to different file bytes.");
  if (job.id !== id) {
    if (job.status === "uploading") return problem(409, "The original upload is still pending. Retry later.", 5);
    return accepted(job.id, job.status);
  }
  try {
    // FixedLengthStream enforces the byte reservation and preserves R2's required length metadata.
    const fixed = new FixedLengthStream(size);
    const pump = (request.body ?? new Blob([]).stream()).pipeTo(fixed.writable, { signal: AbortSignal.timeout(120000) });
    // Observe the pump immediately, including when a binding rejects synchronously.
    const transferred = pump.then(() => ({ error: null as unknown }), error => ({ error }));
    console.log(JSON.stringify({ provider: "Cloudflare", request: { operation: "R2.put", key: id, size, sha256: sha } }));
    const [stored, transfer] = await Promise.all([
      Promise.resolve().then(() => env.UPLOADS.put(id, fixed.readable, { sha256: sha, httpMetadata: { contentType: "application/octet-stream" } })),
      transferred
    ]);
    if (transfer.error) throw transfer.error;
    const object = stored;
    if (!object) throw new Error("Upload was not persisted.");
    console.log(JSON.stringify({ provider: "Cloudflare", response: { operation: "R2.put", key: id, etag: object.etag, size: object.size } }));
    const transitioned = await query<Job>(env, "UPDATE jobs SET status = 'queued', updated_at = unixepoch() WHERE id = ? AND status = 'uploading' RETURNING *", [id]);
    if (!transitioned.results.length) throw new Error("Upload reservation expired.");
  } catch (error) {
    await query(env, "UPDATE jobs SET status = 'failed', error = 'upload_failed', completed_at = unixepoch() WHERE id = ? AND status = 'uploading'", [id]);
    // If the commit response was lost after a successful transition, leave the durable job for recovery.
    const current = await getJob(env, id);
    if (!current) throw error;
    if (current.status !== "failed") return accepted(id, current.status);
    await deleteUpload(env, id);
    console.error(JSON.stringify({ event: "upload_failed", id, error: String(error) }));
    return problem(400, "Upload failed length, checksum, or deadline validation.");
  }
  // Recovery also dispatches queued records if enqueueing fails or its acknowledgement is lost.
  try { await env.SCANS.send({ id }); }
  catch (error) { console.error(JSON.stringify({ event: "dispatch_deferred", id, error: String(error) })); }
  return accepted(id, "queued");
}

function accepted(id: string, status: string): Response {
  const location = `/scan/jobs/${id}`;
  return Response.json({ id, status, statusUrl: location }, { status: 202, headers: { Location: location, "Cache-Control": "no-store", "Retry-After": "2" } });
}

export async function lookup(env: Env, id: string): Promise<Response> {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(id)) return problem(404, "Job not found.");
  const job = await getJob(env, id);
  return job ? Response.json(jobResponse(job), { headers: { "Cache-Control": "no-store" } }) : problem(404, "Job not found.");
}

export async function processJob(env: Env, id: string): Promise<boolean> {
  const lease = crypto.randomUUID();
  const job = await claimJob(env, id, lease);
  if (!job) {
    const current = await getJob(env, id);
    return !current || current.status === "completed" || current.status === "failed";
  }
  try {
    const deadline = AbortSignal.timeout(660000);
    const container = getContainer(env.SCANNER, "scanner");
    await container.startAndWaitForPorts({ cancellationOptions: { abort: deadline, instanceGetTimeoutMS: 60000, portReadyTimeoutMS: 30000 } });
    const warmupUntil = Date.now() + 300000;
    for (;;) {
      const readiness = await container.fetch(new Request("http://scanner/ready", {
        headers: { Authorization: `Bearer ${env.SCANNER_API_KEY}` }, signal: AbortSignal.any([deadline, AbortSignal.timeout(10000)])
      }));
      await readiness.body?.cancel();
      if (readiness.ok) break;
      if (readiness.status !== 503 || Date.now() >= warmupUntil) throw new Error("scanner_not_ready");
      await new Promise(resolve => setTimeout(resolve, 5000));
      deadline.throwIfAborted();
    }
    console.log(JSON.stringify({ provider: "Cloudflare", request: { operation: "R2.get", key: id } }));
    const object = await env.UPLOADS.get(id);
    console.log(JSON.stringify({ provider: "Cloudflare", response: { operation: "R2.get", key: id, size: object?.size, etag: object?.etag } }));
    if (!object || object.size !== job.size) throw new Error("upload_missing_or_invalid");
    const response = await container.fetch(new Request("http://scanner/scan", {
      method: "POST", body: object.body, headers: { Authorization: `Bearer ${env.SCANNER_API_KEY}`, "Content-Length": String(job.size), "Content-Type": "application/octet-stream" },
      signal: deadline,
    }));
    if (!response.ok) { await response.body?.cancel(); throw new Error(`scanner_http_${response.status}`); }
    const result = await response.json<Verdict>();
    if (!validVerdict(result, job)) throw new Error("invalid_scan_result");
    if (result.verdict === "error") throw new Error(result.reason);
    if (!await completeJob(env, id, lease, result)) return false;
    await deleteUpload(env, id);
    console.log(JSON.stringify({ event: "scan_completed", id, verdict: result.verdict, queueAgeSeconds: Date.now()/1000-job.created_at, attempts: job.attempts }));
    return true;
  } catch (error) {
    console.error(JSON.stringify({ event: "scan_attempt_failed", id, attempt: job.attempts, error: String(error) }));
    await query(env, `UPDATE jobs SET status = CASE WHEN attempts >= 3 THEN 'failed' ELSE 'queued' END,
      error = 'scan_attempt_failed', completed_at = CASE WHEN attempts >= 3 THEN unixepoch() ELSE NULL END,
      available_at = unixepoch()+60, lease_token = NULL, lease_until = NULL, updated_at = unixepoch()
      WHERE id = ? AND status = 'processing' AND lease_token = ?`, [id, lease]);
    return false;
  }
}

export function validVerdict(result: Verdict, job: Pick<Job, "sha256" | "size">): boolean {
  return result !== null && typeof result === "object" && ["clean","infected","inconclusive","error"].includes(result.verdict) &&
    typeof result.clean === "boolean" && result.clean === (result.verdict === "clean") && result.sha256 === job.sha256 && result.size === job.size &&
    result.engine === "ClamAV" && typeof result.scanId === "string" && result.scanId.length > 0 &&
    typeof result.reason === "string" && result.reason.length > 0 && typeof result.signatureVersion === "string" && result.signatureVersion.length > 0 &&
    typeof result.engineVersion === "string" && result.engineVersion.length > 0 && typeof result.signatureDate === "string" && Number.isFinite(Date.parse(result.signatureDate)) && Date.parse(result.signatureDate) >= Date.now() - 259200000 &&
    Date.parse(result.signatureDate) <= Date.now() + 300000;
}

export async function recover(env: Env): Promise<void> {
  await query(env, `UPDATE jobs SET status = 'failed', error = 'job_expired_or_attempts_exhausted', completed_at = unixepoch(), lease_token = NULL
    WHERE (status = 'uploading' AND created_at < unixepoch()-600)
      OR (status IN ('queued','processing') AND (expires_at < unixepoch() OR attempts >= 3) AND (lease_until IS NULL OR lease_until < unixepoch()))`);
  const pending = await query<Job>(env, `SELECT * FROM jobs WHERE (status = 'queued' AND available_at <= unixepoch())
    OR (status = 'processing' AND lease_until < unixepoch()) ORDER BY created_at LIMIT 100`);
  if (pending.results.length) {
    try { await env.SCANS.sendBatch(pending.results.map(job => ({ body: { id: job.id } }))); }
    catch (error) { console.error(JSON.stringify({ event: "recovery_dispatch_deferred", error: String(error) })); }
  }
  const expired = await query<Job>(env, "SELECT * FROM jobs WHERE status IN ('completed','failed') AND blob_deleted = 0 LIMIT 100");
  for (const job of expired.results) {
    try { await deleteUpload(env, job.id); }
    catch (error) { console.error(JSON.stringify({ event: "cleanup_deferred", id: job.id, error: String(error) })); }
  }
  await query(env, "DELETE FROM jobs WHERE completed_at < unixepoch()-604800 AND blob_deleted = 1");
  console.log(JSON.stringify({ event: "recovery", dispatched: pending.results.length, cleaned: expired.results.length,
    oldestPendingAgeSeconds: pending.results.length ? Date.now()/1000-pending.results[0].created_at : 0 }));
}

export async function claimJob(env: Env, id: string, lease: string): Promise<Job | undefined> {
  const claimed = await query<Job>(env, `UPDATE jobs SET status = 'processing', lease_token = ?, lease_until = unixepoch()+720,
    attempts = attempts+1, updated_at = unixepoch()
    WHERE id = ? AND expires_at > unixepoch() AND attempts < 3 AND
      ((status = 'queued' AND available_at <= unixepoch()) OR (status = 'processing' AND lease_until < unixepoch())) RETURNING *`, [lease, id]);
  return claimed.results[0];
}

export async function completeJob(env: Env, id: string, lease: string, result: Verdict): Promise<boolean> {
    const committed = await query<Job>(env, `UPDATE jobs SET status = 'completed', error = NULL, result = ?, completed_at = unixepoch(), updated_at = unixepoch(),
      lease_token = NULL, lease_until = NULL WHERE id = ? AND lease_token = ? AND lease_until > unixepoch() RETURNING *`, [JSON.stringify(result), id, lease]);
    return committed.results.length > 0;
}
