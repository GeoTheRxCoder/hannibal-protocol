namespace Hannibal.Core.Storage;

/// <summary>
/// Every SQL statement the Core store issues. tests/python/test_sql_statements.py
/// prepares each constant against the migrated schema, so a typo fails CI
/// even where the C# cannot be executed.
/// </summary>
public static class Sql
{
    public const string EventSeqById = "SELECT event_seq FROM security_events WHERE event_id=?";
    public const string InsertEvent = "INSERT INTO security_events(event_id,schema_version,device_id,source_agent,event_type,observed_ms,ingested_ms,correlation_id,subject_key,privacy_class,payload_json) VALUES(?,1,?,'Sentry',?,?,?,?,?,'local_only',?)";
    public const string InsertEventRoot = "INSERT INTO event_roots(event_seq,root_event_id,capture_channel,collector_id) VALUES(?,?,?,?)";
    public const string ReadEventsAfter = "SELECT e.event_seq,e.event_id,e.device_id,e.event_type,e.observed_ms,e.subject_key,e.payload_json,r.root_event_id,r.capture_channel,r.collector_id FROM security_events e JOIN event_roots r ON r.event_seq=e.event_seq WHERE e.event_seq>? ORDER BY e.event_seq LIMIT ?";
    public const string GetOffset = "SELECT last_event_seq FROM consumer_offsets WHERE consumer_name=?";
    public const string UpsertOffset = "INSERT INTO consumer_offsets(consumer_name,last_event_seq,updated_ms) VALUES(?,?,?) ON CONFLICT(consumer_name) DO UPDATE SET last_event_seq=excluded.last_event_seq, updated_ms=excluded.updated_ms WHERE excluded.last_event_seq>=consumer_offsets.last_event_seq";
    public const string RootOnOtherChannel = "SELECT 1 FROM event_roots WHERE root_event_id=? AND capture_channel<>? LIMIT 1";

    public const string UpsertNode = "INSERT INTO graph_nodes(node_id,device_id,node_type,identity_key,first_seen_ms,last_seen_ms) VALUES(?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET last_seen_ms=MAX(last_seen_ms,excluded.last_seen_ms), first_seen_ms=MIN(first_seen_ms,excluded.first_seen_ms)";
    public const string UpsertEdge = "INSERT INTO graph_edges(edge_id,source_node_id,target_node_id,relation_type,first_seen_ms,last_seen_ms,confidence) VALUES(?,?,?,?,?,?,?) ON CONFLICT(edge_id) DO UPDATE SET last_seen_ms=MAX(last_seen_ms,excluded.last_seen_ms), first_seen_ms=MIN(first_seen_ms,excluded.first_seen_ms), confidence=MAX(confidence,excluded.confidence)";
    public const string InsertRawEdgeObs = "INSERT OR IGNORE INTO raw_edge_observations(edge_id,event_seq,root_event_id,observed_ms,device_id) VALUES(?,?,?,?,?)";
    public const string LoadEdgeObs = "SELECT s.identity_key,s.node_type,t.identity_key,t.node_type,e.relation_type,o.device_id,o.observed_ms,e.confidence,o.event_seq,o.root_event_id FROM raw_edge_observations o JOIN graph_edges e ON e.edge_id=o.edge_id JOIN graph_nodes s ON s.node_id=e.source_node_id JOIN graph_nodes t ON t.node_id=e.target_node_id WHERE o.device_id=? AND o.observed_ms BETWEEN ? AND ? ORDER BY o.observed_ms LIMIT ?";

    public const string IncidentByKey = "SELECT incident_id FROM incident_keys WHERE device_id=? AND correlation_key=?";
    public const string InsertIncident = "INSERT INTO incidents(incident_id,device_id,status,severity,confidence,opened_ms,updated_ms,reason_json) VALUES(?,?,'open',0.0,0.0,?,?,'{}')";
    public const string InsertIncidentKey = "INSERT INTO incident_keys(device_id,correlation_key,incident_id) VALUES(?,?,?)";
    public const string UpdateIncident = "UPDATE incidents SET status=?, severity=?, confidence=?, updated_ms=?, reason_json=? WHERE incident_id=?";
    public const string SetIncidentTarget = "UPDATE incident_keys SET target_kind=?, target_key=?, target_sha256=? WHERE incident_id=?";
    public const string SelectIncidents = "SELECT i.incident_id,i.device_id,k.correlation_key,i.status,i.severity,i.confidence,i.opened_ms,i.updated_ms,i.reason_json,k.target_kind,k.target_key,k.target_sha256 FROM incidents i JOIN incident_keys k ON k.incident_id=i.incident_id";

    public const string InsertEvidence = "INSERT OR IGNORE INTO evidence_records(evidence_id,incident_id,source_event_seq,device_id,subject_key,evidence_family,capture_channel,producer_id,observed_ms,trust_status,confidence) VALUES(?,?,?,?,?,?,?,?,?,?,?)";
    public const string InsertEvidenceRoot = "INSERT OR IGNORE INTO evidence_roots(evidence_id,root_event_id) VALUES(?,?)";
    public const string InsertDerivation = "INSERT OR IGNORE INTO evidence_derivations(child_evidence_id,parent_evidence_id) VALUES(?,?)";
    public const string ParentsOf = "SELECT parent_evidence_id FROM evidence_derivations WHERE child_evidence_id=?";
    public const string RootsOf = "SELECT root_event_id FROM evidence_roots WHERE evidence_id=?";
    public const string EvidenceByIncident = "SELECT evidence_id,incident_id,device_id,subject_key,evidence_family,capture_channel,producer_id,observed_ms,trust_status,confidence FROM evidence_records WHERE incident_id=? ORDER BY observed_ms,evidence_id";
    public const string InsertHypothesis = "INSERT OR REPLACE INTO attack_hypotheses(hypothesis_id,incident_id,generated_ms,hypothesis_kind,status,explanation_json,evidence_root_count) VALUES(?,?,?,?,'hypothesis',?,?)";
    public const string LatestHypothesis = "SELECT explanation_json FROM attack_hypotheses WHERE incident_id=? ORDER BY generated_ms DESC LIMIT 1";

    public const string InsertDecision = "INSERT INTO policy_decisions(decision_id,incident_id,policy_id,decision_ms,action_type,outcome,reason_code,evidence_json) VALUES(?,?,NULL,?,?,?,?,?)";
    public const string InsertDecisionEvidence = "INSERT OR IGNORE INTO policy_decision_evidence(decision_id,evidence_id) VALUES(?,?)";
    public const string LatestDecision = "SELECT reason_code,action_type,decision_ms FROM policy_decisions WHERE incident_id=? ORDER BY decision_ms DESC, rowid DESC LIMIT 1";
    public const string UpsertContainment = "INSERT INTO containment_actions(action_id,idempotency_key,decision_id,device_id,action_type,target_type,target_key,precondition_json,state,created_ms,updated_ms,expires_ms,rollback_token,broker_receipt_json) VALUES(?,?,?,?,?,?,?,'{\"simulated\":true}',?,?,?,?,?,?) ON CONFLICT(idempotency_key) DO UPDATE SET state=excluded.state, updated_ms=excluded.updated_ms, broker_receipt_json=excluded.broker_receipt_json";
    public const string ContainmentByIncident = "SELECT a.action_id,a.action_type,a.target_key,a.state,a.expires_ms,a.rollback_token,a.created_ms FROM containment_actions a JOIN policy_decisions d ON d.decision_id=a.decision_id WHERE d.incident_id=? ORDER BY a.created_ms";

    public const string ExpireContainment = "UPDATE containment_actions SET state='expired', updated_ms=? WHERE state='executed' AND expires_ms IS NOT NULL AND expires_ms<=?";
    public const string ReopenUncontained = "UPDATE incidents SET status='investigating', updated_ms=? WHERE status='contained' AND NOT EXISTS (SELECT 1 FROM containment_actions a JOIN policy_decisions d ON d.decision_id=a.decision_id WHERE d.incident_id=incidents.incident_id AND a.state='executed')";
    public const string RollbackContainment = "UPDATE containment_actions SET state='rolled_back', updated_ms=? WHERE action_id=?";
    public const string ResolveByAction = "UPDATE incidents SET status='resolved', updated_ms=? WHERE incident_id=(SELECT d.incident_id FROM containment_actions a JOIN policy_decisions d ON d.decision_id=a.decision_id WHERE a.action_id=?)";

    public const string UpsertCanary = "INSERT INTO canary_manifest(canary_id,device_id,decoy_kind,location,file_identity_key,sha256,size_bytes,status,updated_ms) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(canary_id) DO UPDATE SET file_identity_key=excluded.file_identity_key, sha256=excluded.sha256, size_bytes=excluded.size_bytes, status=excluded.status, updated_ms=excluded.updated_ms";
    public const string ListCanaries = "SELECT canary_id,device_id,decoy_kind,location,file_identity_key,sha256,size_bytes,status FROM canary_manifest WHERE device_id=? ORDER BY location";
    public const string MarkCanary = "UPDATE canary_manifest SET status=?, updated_ms=? WHERE canary_id=?";

    public const string GetLadder = "SELECT rung,entered_ms,expires_ms FROM isolation_ladder WHERE device_id=? AND subject_key=?";
    public const string UpsertLadder = "INSERT INTO isolation_ladder(device_id,subject_key,rung,entered_ms,expires_ms,decision_id,simulated) VALUES(?,?,?,?,?,?,1) ON CONFLICT(device_id,subject_key) DO UPDATE SET rung=excluded.rung, entered_ms=excluded.entered_ms, expires_ms=excluded.expires_ms, decision_id=excluded.decision_id";
    public const string ListLadder = "SELECT subject_key,rung,entered_ms,expires_ms FROM isolation_ladder WHERE device_id=? ORDER BY rung DESC, entered_ms DESC";

    public const string UpsertAxis = "INSERT INTO axis_coverage(device_id,axis,capture_channel,status,updated_ms) VALUES(?,?,?,?,?) ON CONFLICT(device_id,axis) DO UPDATE SET capture_channel=excluded.capture_channel, status=excluded.status, updated_ms=excluded.updated_ms";
    public const string ListAxes = "SELECT axis,capture_channel,status FROM axis_coverage WHERE device_id=? ORDER BY axis";

    public const string BundleVersion = "SELECT version FROM bundle_state WHERE bundle_type=?";
    public const string UpsertBundle = "INSERT INTO bundle_state(bundle_type,bundle_id,version,sha256,accepted_ms,expires_ms) VALUES(?,?,?,?,?,?) ON CONFLICT(bundle_type) DO UPDATE SET bundle_id=excluded.bundle_id, version=excluded.version, sha256=excluded.sha256, accepted_ms=excluded.accepted_ms, expires_ms=excluded.expires_ms WHERE excluded.version>=bundle_state.version";
    public const string ListBundles = "SELECT bundle_type,bundle_id,version,sha256,expires_ms FROM bundle_state ORDER BY bundle_type";
    public const string UpsertIndicator = "INSERT INTO malicious_file_indicators(indicator_id,sha256,bundle_id,bundle_signature_ref,verified_ms,valid_until_ms,verification_status) VALUES(?,?,?,?,?,?,?) ON CONFLICT(indicator_id) DO UPDATE SET bundle_id=excluded.bundle_id, bundle_signature_ref=excluded.bundle_signature_ref, verified_ms=excluded.verified_ms, valid_until_ms=excluded.valid_until_ms, verification_status=excluded.verification_status";
    public const string IndicatorsBySha = "SELECT indicator_id,sha256,bundle_id,valid_until_ms,verification_status FROM malicious_file_indicators WHERE sha256=?";

    public const string UpsertCollector = "INSERT INTO collector_health(collector_id,capture_channel,last_seq,last_seen_ms,lost_events,rejected_events,status) VALUES(?,?,?,?,?,?,?) ON CONFLICT(collector_id) DO UPDATE SET capture_channel=excluded.capture_channel, last_seq=excluded.last_seq, last_seen_ms=excluded.last_seen_ms, lost_events=excluded.lost_events, rejected_events=excluded.rejected_events, status=excluded.status";
    public const string ListCollectors = "SELECT collector_id,capture_channel,last_seq,last_seen_ms,lost_events,rejected_events,status FROM collector_health ORDER BY collector_id";
    public const string UpsertHeartbeat = "INSERT INTO agent_heartbeats(agent_id,last_seen_ms,last_event_seq,health_status,details_json) VALUES(?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET last_seen_ms=excluded.last_seen_ms, last_event_seq=excluded.last_event_seq, health_status=excluded.health_status, details_json=excluded.details_json";
    public const string ListHeartbeats = "SELECT agent_id,last_seen_ms,last_event_seq,health_status,details_json FROM agent_heartbeats ORDER BY agent_id";

    public const string InsertHashFirstSeen = "INSERT OR IGNORE INTO hash_first_seen(device_id,sha256,first_seen_ms) VALUES(?,?,?)";
    public const string HashFirstSeen = "SELECT first_seen_ms FROM hash_first_seen WHERE device_id=? AND sha256=?";
    public const string InsertBaseline = "INSERT OR IGNORE INTO baseline_state(device_id,baseline_started_ms) VALUES(?,?)";
    public const string GetBaseline = "SELECT baseline_started_ms FROM baseline_state WHERE device_id=?";
    public const string InsertFeatureWindow = "INSERT OR IGNORE INTO feature_windows(feature_window_id,device_id,process_key,started_ms,ended_ms,feature_schema,feature_json,coverage,model_id,anomaly_ratio) VALUES(?,?,?,?,?,?,?,?,NULL,?)";
}
