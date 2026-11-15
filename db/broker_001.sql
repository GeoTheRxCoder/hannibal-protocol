-- Containment Broker private database ("the Ribat"). The Core service has NO
-- write access to this file. Write-ahead intent log + the broker's own audit chain.
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS broker_intents (
  action_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  decision_id TEXT NOT NULL,
  command TEXT NOT NULL CHECK(command IN ('SimulateNetworkBlock','SimulateQuarantine')),
  device_id TEXT NOT NULL,
  target_key TEXT NOT NULL,
  target_sha256 TEXT,
  state TEXT NOT NULL CHECK(state IN
    ('INTENDED','APPLIED','EXPIRED','ROLLED_BACK','FAILED','FAILED_ON_CRASH')),
  simulated INTEGER NOT NULL CHECK(simulated = 1),
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL,
  expires_ms INTEGER,
  rollback_token TEXT UNIQUE,
  detail_json TEXT NOT NULL CHECK(json_valid(detail_json))
);
CREATE INDEX IF NOT EXISTS ix_broker_intents_state ON broker_intents(state, expires_ms);

CREATE TABLE IF NOT EXISTS audit_chain (
  audit_seq INTEGER PRIMARY KEY AUTOINCREMENT,
  recorded_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  body_json TEXT NOT NULL CHECK(json_valid(body_json)),
  prev_hash TEXT NOT NULL CHECK(length(prev_hash) = 64),
  entry_hash TEXT NOT NULL UNIQUE CHECK(length(entry_hash) = 64)
);

CREATE TABLE IF NOT EXISTS broker_kv (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);
