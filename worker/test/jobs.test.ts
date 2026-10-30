import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:workers";
import schema from "../migrations/0001_jobs.sql?raw";
import worker from "../src/index";
import { getJob, query } from "../src/storage";
import { claimJob, completeJob, processJob, recover, submit, validVerdict } from "../src/jobs";
import type { Env, Job, Verdict } from "../src/types";
const bindings = env as unknown as Env;
const bytes = new TextEncoder().encode("clean test content");
const sha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), b => b.toString(16).padStart(2, "0")).join("");
function upload(key = crypto.randomUUID(), hash = sha): Request {
  return new Request("https://scanner.test/scan/jobs", { method: "POST", body: bytes,
    headers: { "Idempotency-Key": key, "X-Content-SHA256": hash, "Content-Length": String(bytes.length), Authorization: `Bearer ${bindings.SCANNER_API_KEY}` } });
}
async function enqueue(key = crypto.randomUUID()): Promise<Job> {
  const response = await submit(upload(key), bindings);
  expect(response.status).toBe(202);
  const accepted = await response.json<{ id: string }>();
  return (await getJob(bindings, accepted.id))!;
}
beforeEach(async () => {
  await bindings.JOBS.exec("DROP TABLE IF EXISTS jobs;");
  for (const sql of schema.split(";").filter(x => x.trim())) await bindings.JOBS.prepare(sql).run();
  const objects = await bindings.UPLOADS.list();
  if (objects.objects.length) await bindings.UPLOADS.delete(objects.objects.map(x => x.key));
});
describe("durable jobs using real local D1 and R2", () => {
  it("persists bytes and job state before accepting; replay returns the same job", async () => {
    const key = crypto.randomUUID();
    const job = await enqueue(key);
    expect(job.status).toBe("queued");
    expect(await (await bindings.UPLOADS.get(job.id))!.text()).toBe("clean test content");
    const replay = await submit(upload(key), bindings);
    expect((await replay.json<{ id: string }>()).id).toBe(job.id);
    expect((await query(bindings, "SELECT * FROM jobs")).results).toHaveLength(1);
  });
  it("rejects reuse of an idempotency key for different bytes", async () => {
    const key = crypto.randomUUID(); await enqueue(key);
    expect((await submit(upload(key, "0".repeat(64)), bindings)).status).toBe(409);
  });
  it("does not accept a checksum mismatch and removes partial state", async () => {
    expect((await submit(upload(crypto.randomUUID(), "0".repeat(64)), bindings)).status).toBe(400);
    const records = await query<Job>(bindings, "SELECT * FROM jobs");
    expect(records.results[0].status).toBe("failed");
    expect((await bindings.UPLOADS.list()).objects).toHaveLength(0);
  });
  it("cleans up a request stream that fails midway through upload", async () => {
    const broken = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(bytes.slice(0, 2)); controller.close(); }
    });
    const original = upload();
    const response = await submit(new Request(original.url, { method: "POST", headers: original.headers, body: broken }), bindings);
    expect(response.status).toBe(400);
    expect((await query<Job>(bindings, "SELECT * FROM jobs")).results[0].status).toBe("failed");
    expect((await bindings.UPLOADS.list()).objects).toHaveLength(0);
  });
  it("never accepts work when job storage is unavailable", async () => {
    await bindings.JOBS.exec("DROP TABLE jobs");
    const response = await worker.fetch(upload(), bindings);
    expect(response.status).toBe(503);
    expect((await bindings.UPLOADS.list()).objects).toHaveLength(0);
  });
  it("reserves upload capacity atomically before consuming bytes", async () => {
    for (let i = 0; i < 8; i++) await query(bindings, "INSERT INTO jobs (id,idempotency_key,sha256,size,status) VALUES (?,?,?,0,'uploading')", [crypto.randomUUID(),crypto.randomUUID(),sha]);
    expect((await submit(upload(), bindings)).status).toBe(429);
    expect((await bindings.UPLOADS.list()).objects).toHaveLength(0);
  });
  it("keeps bytes and retries when the container transport is unavailable", async () => {
    const job = await enqueue();
    // No container transport is bound: exercise a platform outage through the real job processor.
    expect(await processJob(bindings, job.id)).toBe(false);
    const retried = (await getJob(bindings, job.id))!;
    expect(retried.status).toBe("queued"); expect(retried.attempts).toBe(1);
    expect(await bindings.UPLOADS.head(job.id)).not.toBeNull();
  });
  it("does not steal a live lease and recovers an expired one", async () => {
    const job = await enqueue();
    await query(bindings, "UPDATE jobs SET status='processing', lease_token='owner', lease_until=unixepoch()+720, attempts=1 WHERE id=?", [job.id]);
    expect(await processJob(bindings, job.id)).toBe(false);
    expect((await getJob(bindings, job.id))!.attempts).toBe(1);
    await query(bindings, "UPDATE jobs SET lease_until=unixepoch()-1 WHERE id=?", [job.id]);
    await processJob(bindings, job.id);
    expect((await getJob(bindings, job.id))!.attempts).toBe(2);
  });
  it("only one concurrent processor acquires a job and stale completion is fenced", async () => {
    const job = await enqueue();
    const [first, second] = await Promise.all([claimJob(bindings, job.id, "first"), claimJob(bindings, job.id, "second")]);
    expect([first, second].filter(Boolean)).toHaveLength(1);
    const owner = first ? "first" : "second";
    await query(bindings, "UPDATE jobs SET lease_until=unixepoch()-1 WHERE id=?", [job.id]);
    expect(await claimJob(bindings, job.id, "replacement")).toBeDefined();
    const verdict = { clean: true, verdict: "clean", reason: "no_threat_detected", sha256: sha, size: bytes.length, scanId: crypto.randomUUID(),
      engine: "ClamAV", engineVersion: "ClamAV 1.4", signatureVersion: "12345", signatureDate: new Date().toISOString() } as Verdict;
    expect(await completeJob(bindings, job.id, owner, verdict)).toBe(false);
    expect(await completeJob(bindings, job.id, "replacement", verdict)).toBe(true);
    expect(await completeJob(bindings, job.id, "replacement", verdict)).toBe(false);
    expect((await getJob(bindings, job.id))!.status).toBe("completed");
  });
  it("bounds retries and recovers cleanup after a process is lost", async () => {
    const job = await enqueue();
    await query(bindings, "UPDATE jobs SET status='processing', attempts=3, lease_until=unixepoch()-1 WHERE id=?", [job.id]);
    await recover(bindings);
    const failed = (await getJob(bindings, job.id))!;
    expect(failed.status).toBe("failed"); expect(failed.blob_deleted).toBe(1);
    expect(await bindings.UPLOADS.head(job.id)).toBeNull();
    expect(await processJob(bindings, job.id)).toBe(true);
  });
  it("reclaims abandoned uploads and expires terminal records only after cleanup", async () => {
    const job = await enqueue();
    await query(bindings, "UPDATE jobs SET status='uploading', created_at=unixepoch()-601 WHERE id=?", [job.id]);
    await recover(bindings);
    expect((await getJob(bindings, job.id))!.status).toBe("failed");
    await query(bindings, "UPDATE jobs SET completed_at=unixepoch()-604801 WHERE id=?", [job.id]);
    await recover(bindings);
    expect(await getJob(bindings, job.id)).toBeUndefined();
  });
  it("rejects unauthenticated submissions before storage", async () => {
    const request = upload(); request.headers.delete("Authorization");
    expect((await worker.fetch(request, bindings)).status).toBe(401);
    expect((await query(bindings, "SELECT * FROM jobs")).results).toHaveLength(0);
  });
  it("rejects a clean verdict for different bytes or inconsistent inspection state", () => {
    const result = { clean: true, verdict: "clean", reason: "no_threat_detected", sha256: sha, size: bytes.length, scanId: crypto.randomUUID(),
      engine: "ClamAV", engineVersion: "ClamAV 1.4", signatureVersion: "12345", signatureDate: new Date().toISOString() } as Verdict;
    expect(validVerdict(result, { sha256: sha, size: bytes.length })).toBe(true);
    expect(validVerdict({ ...result, verdict: "inconclusive" }, { sha256: sha, size: bytes.length })).toBe(false);
    expect(validVerdict(result, { sha256: "0".repeat(64), size: bytes.length })).toBe(false);
  });
});
