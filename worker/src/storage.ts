import type { Env, Job } from "./types";

// Keep Cloudflare request/response operation logging enabled for every environment.
export async function query<T>(env: Env, sql: string, params: (string | number | null)[] = []): Promise<D1Result<T>> {
  console.log(JSON.stringify({ provider: "Cloudflare", request: { sql, params } }));
  const result = await env.JOBS.prepare(sql).bind(...params).all<T>();
  console.log(JSON.stringify({ provider: "Cloudflare", response: result }));
  if (!result.success) throw new Error("Job database operation failed.");
  return result;
}
export async function getJob(env: Env, id: string): Promise<Job | undefined> {
  return (await query<Job>(env, "SELECT * FROM jobs WHERE id = ?", [id])).results[0];
}
export function jobResponse(job: Job) {
  return {
    id: job.id, status: job.status, result: job.result ? JSON.parse(job.result) : null,
    error: job.error, createdAt: new Date(job.created_at * 1000).toISOString(),
    completedAt: job.completed_at === null ? null : new Date(job.completed_at * 1000).toISOString(),
    attempts: job.attempts,
  };
}
export async function deleteUpload(env: Env, id: string): Promise<void> {
  console.log(JSON.stringify({ provider: "Cloudflare", request: { operation: "R2.delete", key: id } }));
  await env.UPLOADS.delete(id);
  console.log(JSON.stringify({ provider: "Cloudflare", response: { operation: "R2.delete", key: id, success: true } }));
  await query(env, "UPDATE jobs SET blob_deleted = 1 WHERE id = ? AND status IN ('completed','failed')", [id]);
}
