PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
  event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
  device_id TEXT NOT NULL,
  source_agent TEXT NOT NULL CHECK(source_agent IN
    ('Sentry','Reconnaissance','ThreatDetection','TacticalML',
     'ThreatAnalysis','CounterOffensive','Overwatch')),
  event_type TEXT NOT NULL,
  observed_ms INTEGER NOT NULL,
  ingested_ms INTEGER NOT NULL,
  correlation_id TEXT,
  subject_key TEXT,
  privacy_class TEXT NOT NULL DEFAULT 'local_only'
    CHECK(privacy_class IN ('local_only','shareable_indicator')),
  payload_json TEXT NOT NULL CHECK(json_valid(payload_json))
);
CREATE INDEX IF NOT EXISTS ix_events_device_time
  ON security_events(device_id, observed_ms);
CREATE INDEX IF NOT EXISTS ix_events_correlation
  ON security_events(correlation_id, event_seq);
CREATE INDEX IF NOT EXISTS ix_events_type_time
  ON security_events(event_type, observed_ms);

CREATE TABLE IF NOT EXISTS consumer_offsets (
  consumer_name TEXT PRIMARY KEY,
  last_event_seq INTEGER NOT NULL DEFAULT 0 CHECK(last_event_seq >= 0),
  updated_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_nodes (
  node_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  node_type TEXT NOT NULL CHECK(node_type IN
    ('Device','Process','FileOccurrence','FileArtifact','NetworkEndpoint',
     'Account','PersistenceEntry','Incident')),
  identity_key TEXT NOT NULL,
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms INTEGER NOT NULL,
  properties_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(properties_json)),
  UNIQUE(device_id, node_type, identity_key),
  CHECK(last_seen_ms >= first_seen_ms)
);
CREATE INDEX IF NOT EXISTS ix_nodes_type_seen
  ON graph_nodes(node_type, last_seen_ms);

CREATE TABLE IF NOT EXISTS graph_edges (
  edge_id TEXT PRIMARY KEY,
  source_node_id TEXT NOT NULL REFERENCES graph_nodes(node_id),
  target_node_id TEXT NOT NULL REFERENCES graph_nodes(node_id),
  relation_type TEXT NOT NULL CHECK(relation_type IN
    ('SPAWNED','EXECUTED','INSTANCE_OF','CONNECTED_TO','OWNS',
     'PERSISTED_AS','RELATED_TO','PART_OF')),
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms INTEGER NOT NULL,
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  properties_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(properties_json)),
  UNIQUE(source_node_id, target_node_id, relation_type),
  CHECK(last_seen_ms >= first_seen_ms)
);
CREATE INDEX IF NOT EXISTS ix_edges_source ON graph_edges(source_node_id, relation_type);
CREATE INDEX IF NOT EXISTS ix_edges_target ON graph_edges(target_node_id, relation_type);

CREATE TABLE IF NOT EXISTS graph_edge_evidence (
  edge_id TEXT NOT NULL REFERENCES graph_edges(edge_id) ON DELETE CASCADE,
  event_seq INTEGER NOT NULL REFERENCES security_events(event_seq),
  PRIMARY KEY(edge_id, event_seq)
);

CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN
    ('open','investigating','contained','resolved','false_positive')),
  severity REAL NOT NULL CHECK(severity BETWEEN 0.0 AND 1.0),
  confidence REAL NOT NULL CHECK(confidence BETWEEN 0.0 AND 1.0),
  opened_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL,
  reason_json TEXT NOT NULL CHECK(json_valid(reason_json))
);
CREATE INDEX IF NOT EXISTS ix_incidents_status_updated
  ON incidents(status, updated_ms);

CREATE TABLE IF NOT EXISTS incident_events (
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
  event_seq INTEGER NOT NULL REFERENCES security_events(event_seq),
  PRIMARY KEY(incident_id, event_seq)
);

CREATE TABLE IF NOT EXISTS policy_rules (
  policy_id TEXT PRIMARY KEY,
  policy_version INTEGER NOT NULL CHECK(policy_version > 0),
  action_type TEXT NOT NULL CHECK(action_type IN
    ('observe','alert','quarantine','temporary_network_block','terminate_process')),
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  constraints_json TEXT NOT NULL CHECK(json_valid(constraints_json)),
  signature_ref TEXT NOT NULL,
  created_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
  decision_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
  policy_id TEXT REFERENCES policy_rules(policy_id),
  decision_ms INTEGER NOT NULL,
  action_type TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('allow','deny','alert','observe')),
  reason_code TEXT NOT NULL,
  evidence_json TEXT NOT NULL CHECK(json_valid(evidence_json))
);
CREATE INDEX IF NOT EXISTS ix_decisions_incident
  ON policy_decisions(incident_id, decision_ms);

CREATE TABLE IF NOT EXISTS containment_actions (
  action_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  decision_id TEXT NOT NULL REFERENCES policy_decisions(decision_id),
  device_id TEXT NOT NULL,
  action_type TEXT NOT NULL CHECK(action_type IN
    ('quarantine','temporary_network_block','terminate_process')),
  target_type TEXT NOT NULL CHECK(target_type IN
    ('FileOccurrence','Process','NetworkEndpoint')),
  target_key TEXT NOT NULL,
  precondition_json TEXT NOT NULL CHECK(json_valid(precondition_json)),
  state TEXT NOT NULL CHECK(state IN
    ('requested','verified','executed','failed','expired','rolled_back')),
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL,
  expires_ms INTEGER,
  rollback_token TEXT,
  broker_receipt_json TEXT CHECK(broker_receipt_json IS NULL OR json_valid(broker_receipt_json))
);
CREATE INDEX IF NOT EXISTS ix_actions_state_expiry
  ON containment_actions(state, expires_ms);

CREATE TABLE IF NOT EXISTS model_versions (
  model_id TEXT PRIMARY KEY,
  feature_schema TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  signature_ref TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN
    ('candidate','staged','active','retired','revoked')),
  created_ms INTEGER NOT NULL,
  activated_ms INTEGER,
  metrics_json TEXT NOT NULL CHECK(json_valid(metrics_json))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_single_active_schema
  ON model_versions(feature_schema) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS candidate_updates (
  candidate_id TEXT PRIMARY KEY,
  model_id TEXT NOT NULL REFERENCES model_versions(model_id),
  evaluation_status TEXT NOT NULL CHECK(evaluation_status IN
    ('proposed','testing','passed','failed','approved','deployed','reverted')),
  metrics_json TEXT NOT NULL CHECK(json_valid(metrics_json)),
  created_ms INTEGER NOT NULL,
  decided_ms INTEGER,
  reviewer_ref TEXT
);

CREATE TABLE IF NOT EXISTS feature_windows (
  feature_window_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  process_key TEXT NOT NULL,
  started_ms INTEGER NOT NULL,
  ended_ms INTEGER NOT NULL,
  feature_schema TEXT NOT NULL,
  feature_json TEXT NOT NULL CHECK(json_valid(feature_json)),
  coverage REAL NOT NULL CHECK(coverage BETWEEN 0.0 AND 1.0),
  model_id TEXT REFERENCES model_versions(model_id),
  anomaly_ratio REAL,
  CHECK(ended_ms > started_ms)
);
CREATE INDEX IF NOT EXISTS ix_feature_device_time
  ON feature_windows(device_id, ended_ms);

CREATE TABLE IF NOT EXISTS agent_heartbeats (
  agent_id TEXT PRIMARY KEY CHECK(agent_id IN
    ('Sentry','Reconnaissance','ThreatDetection','TacticalML',
     'ThreatAnalysis','CounterOffensive','Overwatch')),
  last_seen_ms INTEGER NOT NULL,
  last_event_seq INTEGER NOT NULL DEFAULT 0,
  health_status TEXT NOT NULL CHECK(health_status IN
    ('healthy','degraded','offline','starting')),
  details_json TEXT NOT NULL CHECK(json_valid(details_json))
);

INSERT OR IGNORE INTO schema_migrations(version, applied_ms)
VALUES(1, CAST(strftime('%s','now') AS INTEGER)*1000);
