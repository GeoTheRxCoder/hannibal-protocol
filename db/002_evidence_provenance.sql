-- SPEC-001 v0.5 append-only provenance and graph edge occurrence migration.
-- Apply AFTER 001_initial.sql. Requires SQLite 3.37+ for rigorous STRICT tables.
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS evidence_records (
  evidence_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
  source_event_seq INTEGER REFERENCES security_events(event_seq),
  device_id TEXT NOT NULL,
  subject_key TEXT NOT NULL,
  evidence_family TEXT NOT NULL CHECK (evidence_family IN
    ('Signature','Reputation','Behavior','Graph','MlAnomaly','Exposure')),
  capture_channel TEXT NOT NULL,
  producer_id TEXT NOT NULL,
  observed_ms INTEGER NOT NULL,
  trust_status TEXT NOT NULL CHECK(trust_status IN
    ('unverified','verified','revoked')),
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  CHECK(length(evidence_id) > 0 AND length(subject_key) > 0)
);
CREATE INDEX IF NOT EXISTS ix_evidence_incident_time
 ON evidence_records(incident_id, observed_ms);

-- Each raw observation is a stable, canonical source event (never a generated
-- graph finding). Evidence derived from the same raw observation shares a root.
CREATE TABLE IF NOT EXISTS evidence_roots (
  evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id) ON DELETE CASCADE,
  root_event_id TEXT NOT NULL,
  PRIMARY KEY(evidence_id, root_event_id)
);
CREATE INDEX IF NOT EXISTS ix_evidence_root ON evidence_roots(root_event_id);

-- An explicit DAG of derived findings for audit; reject cycles in application code.
CREATE TABLE IF NOT EXISTS evidence_derivations (
  child_evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id) ON DELETE CASCADE,
  parent_evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id) ON DELETE CASCADE,
  PRIMARY KEY(child_evidence_id,parent_evidence_id),
  CHECK(child_evidence_id <> parent_evidence_id)
);

-- Validated indicator metadata only; verification of the signed parent bundle
-- MUST happen within a separate trusted verifier before setting verified.
CREATE TABLE IF NOT EXISTS malicious_file_indicators (
  indicator_id TEXT PRIMARY KEY,
  sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
  bundle_id TEXT NOT NULL,
  bundle_signature_ref TEXT NOT NULL,
  verified_ms INTEGER NOT NULL,
  valid_until_ms INTEGER NOT NULL,
  verification_status TEXT NOT NULL CHECK(verification_status IN
    ('unverified','verified','revoked')),
  CHECK(valid_until_ms > verified_ms)
);
CREATE INDEX IF NOT EXISTS ix_indicator_sha256
 ON malicious_file_indicators(sha256, verification_status);

CREATE TABLE IF NOT EXISTS graph_edge_observations (
  observation_id TEXT PRIMARY KEY,
  edge_id TEXT NOT NULL REFERENCES graph_edges(edge_id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id),
  event_seq INTEGER NOT NULL REFERENCES security_events(event_seq),
  observed_ms INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  UNIQUE(edge_id,event_seq)
);
CREATE INDEX IF NOT EXISTS ix_graph_edge_observations_time
 ON graph_edge_observations(edge_id,observed_ms);

CREATE TABLE IF NOT EXISTS attack_hypotheses (
  hypothesis_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
  generated_ms INTEGER NOT NULL,
  hypothesis_kind TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN('hypothesis','corroborated','rejected')),
  explanation_json TEXT NOT NULL CHECK(json_valid(explanation_json)),
  evidence_root_count INTEGER NOT NULL CHECK(evidence_root_count >= 0)
);

CREATE TABLE IF NOT EXISTS policy_decision_evidence (
  decision_id TEXT NOT NULL REFERENCES policy_decisions(decision_id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id),
  PRIMARY KEY(decision_id,evidence_id)
);

CREATE TABLE IF NOT EXISTS model_evaluation_reports (
  evaluation_id TEXT PRIMARY KEY,
  model_id TEXT NOT NULL REFERENCES model_versions(model_id),
  cohort TEXT NOT NULL,
  dataset_digest_sha256 TEXT NOT NULL CHECK(length(dataset_digest_sha256)=64),
  test_start_ms INTEGER NOT NULL,
  test_end_ms INTEGER NOT NULL,
  report_json TEXT NOT NULL CHECK(json_valid(report_json)),
  decision TEXT NOT NULL CHECK(decision IN('research','pass','fail','rejected')),
  CHECK(test_end_ms >= test_start_ms)
);

INSERT OR IGNORE INTO schema_migrations(version, applied_ms)
VALUES(2, CAST(strftime('%s','now') AS INTEGER)*1000);
