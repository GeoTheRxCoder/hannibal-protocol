-- SPEC-001 v0.6 beta runtime migration. Apply AFTER 001 and 002.
-- Adds: raw-root bookkeeping, incident correlation, the observation layer that
-- is not coupled to incidents, the tamper-evident audit chain, deception
-- manifest, isolation ladder, axis coverage, bundle rollback state, collector
-- health and the 30-day executable-hash baseline.
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS event_roots (
  event_seq INTEGER PRIMARY KEY REFERENCES security_events(event_seq),
  root_event_id TEXT NOT NULL CHECK(length(root_event_id) > 0),
  capture_channel TEXT NOT NULL CHECK(length(capture_channel) > 0),
  collector_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_event_roots_root ON event_roots(root_event_id);

CREATE TABLE IF NOT EXISTS incident_keys (
  device_id TEXT NOT NULL,
  correlation_key TEXT NOT NULL,
  incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(incident_id) ON DELETE CASCADE,
  target_kind TEXT,
  target_key TEXT,
  target_sha256 TEXT,
  PRIMARY KEY(device_id, correlation_key)
);

CREATE TABLE IF NOT EXISTS raw_edge_observations (
  edge_id TEXT NOT NULL REFERENCES graph_edges(edge_id) ON DELETE CASCADE,
  event_seq INTEGER NOT NULL REFERENCES security_events(event_seq),
  root_event_id TEXT NOT NULL,
  observed_ms INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  PRIMARY KEY(edge_id, event_seq)
);
CREATE INDEX IF NOT EXISTS ix_raw_edge_obs_time ON raw_edge_observations(device_id, observed_ms);

-- "Bronze record": single-writer hash chain. entry_hash =
-- SHA256(prev_hash || 0x1F || recorded_ms || 0x1F || kind || 0x1F || body_json).
CREATE TABLE IF NOT EXISTS audit_chain (
  audit_seq INTEGER PRIMARY KEY AUTOINCREMENT,
  recorded_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  body_json TEXT NOT NULL CHECK(json_valid(body_json)),
  prev_hash TEXT NOT NULL CHECK(length(prev_hash) = 64),
  entry_hash TEXT NOT NULL UNIQUE CHECK(length(entry_hash) = 64)
);

CREATE TABLE IF NOT EXISTS canary_manifest (
  canary_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  decoy_kind TEXT NOT NULL CHECK(decoy_kind IN ('file','credential_file','registry_value')),
  location TEXT NOT NULL,
  file_identity_key TEXT,
  sha256 TEXT,
  size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
  status TEXT NOT NULL CHECK(status IN ('planned','deployed','tripped','retired')),
  updated_ms INTEGER NOT NULL,
  UNIQUE(device_id, location)
);

CREATE TABLE IF NOT EXISTS isolation_ladder (
  device_id TEXT NOT NULL,
  subject_key TEXT NOT NULL,
  rung INTEGER NOT NULL CHECK(rung BETWEEN 0 AND 3),
  entered_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL,
  decision_id TEXT,
  simulated INTEGER NOT NULL CHECK(simulated IN (0,1)),
  PRIMARY KEY(device_id, subject_key),
  CHECK(expires_ms >= entered_ms)
);

CREATE TABLE IF NOT EXISTS axis_coverage (
  device_id TEXT NOT NULL,
  axis TEXT NOT NULL,
  capture_channel TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('watched','degraded','unwatched')),
  updated_ms INTEGER NOT NULL,
  PRIMARY KEY(device_id, axis)
);

CREATE TABLE IF NOT EXISTS bundle_state (
  bundle_type TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK(version > 0),
  sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
  accepted_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS collector_health (
  collector_id TEXT PRIMARY KEY,
  capture_channel TEXT NOT NULL,
  last_seq INTEGER NOT NULL DEFAULT 0,
  last_seen_ms INTEGER NOT NULL,
  lost_events INTEGER NOT NULL DEFAULT 0,
  rejected_events INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('healthy','degraded','offline'))
);

CREATE TABLE IF NOT EXISTS hash_first_seen (
  device_id TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
  first_seen_ms INTEGER NOT NULL,
  PRIMARY KEY(device_id, sha256)
);

CREATE TABLE IF NOT EXISTS baseline_state (
  device_id TEXT PRIMARY KEY,
  baseline_started_ms INTEGER NOT NULL
);

INSERT OR IGNORE INTO schema_migrations(version, applied_ms)
VALUES(3, CAST(strftime('%s','now') AS INTEGER)*1000);
