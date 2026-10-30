import type { ScannerContainer } from "./index";
export interface Env {
  SCANNER: DurableObjectNamespace<ScannerContainer>;
  JOBS: D1Database;
  UPLOADS: R2Bucket;
  SCANS: Queue<{ id: string }>;
  SCANNER_API_KEY: string;
}
export interface Job {
  id: string;
  idempotency_key: string;
  sha256: string;
  size: number;
  status: "uploading" | "queued" | "processing" | "completed" | "failed";
  created_at: number;
  updated_at: number;
  available_at: number;
  expires_at: number;
  lease_token: string | null;
  lease_until: number | null;
  attempts: number;
  result: string | null;
  error: string | null;
  completed_at: number | null;
  blob_deleted: number;
}
export interface Verdict {
  clean: boolean;
  verdict: "clean" | "infected" | "inconclusive" | "error";
  reason: string;
  sha256: string;
  size: number;
  scanId: string;
  engine: string;
  engineVersion: string;
  signatureVersion: string;
  signatureDate: string;
}
