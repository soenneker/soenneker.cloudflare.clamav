CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL CHECK(size >= 0 AND size <= 104857600),
  status TEXT NOT NULL CHECK(status IN ('uploading','queued','processing','completed','failed')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  available_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL DEFAULT (unixepoch() + 86400),
  lease_token TEXT,
  lease_until INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0,
  result TEXT,
  error TEXT,
  completed_at INTEGER,
  blob_deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX jobs_dispatch ON jobs(status, available_at, lease_until);
CREATE INDEX jobs_cleanup ON jobs(status, blob_deleted, completed_at);
CREATE INDEX jobs_expiry ON jobs(expires_at);
