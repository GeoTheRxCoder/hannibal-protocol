# SPEC-001 — Hannibal Protocol: Method Part 2 (v0.4)

Status: **proposed implementation reference, not production antivirus software**.
Platform: Windows 11 first; macOS/Android/iOS later.
Cloud: local-first, opt-in cloud intelligence.
Response: autonomous DEFENSIVE containment only on authorized systems.

## A. Runtime topology and durable messaging

- `Hannibal.CoreService`: hosts logical Overwatch/Sentry/Reconnaissance/
  Detection/TacticalML/ThreatAnalysis/CounterOffensive modules and a durable
  SQLite journal. Separate the GUI and privileged containment broker.
- `Hannibal.ContainmentBroker`: privileged Windows service exposing a narrowly
  scoped authenticated IPC contract. No generic command runner.
- `Hannibal.Desktop`: unprivileged WPF user interface with limited IPC grants.
- `Hannibal.ModelLab`: offline Python training/evaluation; no live privileges.
- `Hannibal.CloudGateway`: disabled by default; explicit opt-in for threats and
  model metadata; local protection unaffected by cloud outage.

**Delivery**: append event in a transaction, write its sequence number,
notify subscribers through a bounded in-memory channel (`FullMode.Wait` for
critical events), then each consumer:
1. Read event rows after its saved consumer offset in monotonically increasing
   `event_seq` order.
2. Apply idempotent graph/incident mutations and advance `consumer_offsets`
   in the **same SQLite transaction**.
3. On crash, replay any uncommitted events. Consumers handle duplicates by
   unique event ID, unique node/edge identity and containment idempotency key.
4. Use separate telemetry queues for bulk event handling. Never silently drop
   high-priority events; report degraded health on pressure.
5. Serialize SQLite writes via a queue/lock, and keep transactions short.
6. Plan event retention with a checkpoint-safe pruning procedure and exported
   signed summaries; never prune evidence linked to an open incident.

SQLite `PRAGMA foreign_keys=ON` and `PRAGMA busy_timeout=5000` apply on each
new connection. `journal_mode=WAL` is set during initialization. Protect
database, WAL and SHM files with dedicated Windows ACLs. Audit tampering,
backups and crash recovery. Do not claim SQLite is intrinsically tamper-proof.

## B. Schema and entity identity

Run `db/001_initial.sql`. All timestamps are UTC Unix milliseconds; `*_id`
fields are UUID strings in normal use. Database constraint checks prevent
invalid enumerations, duplicate node identities, and broken graph foreign keys.

**Process identity**: `device_id + boot_session_id + PID + creation_time`,
not PID alone. PIDs are reused. At containment time recheck the identity,
path, signer and opened process handle before executing any action.

**FileOccurrence**: `device_id + volume/file_identifier + observed_path`,
a local occurrence (case and file rename rules must be normalized using
Windows APIs). **FileArtifact**: SHA-256 of file bytes, as a separate node.
Never equate a path alone with an immutable file artifact; check hash
before quarantine. NetworkEndpoint identity includes protocol, remote IP,
port and scope, not a hostname alone. Account identities use scoped SIDs.

**Permitted graph edges**:
- `Process -SPAWNED-> Process`
- `Process -EXECUTED-> FileOccurrence`
- `FileOccurrence -INSTANCE_OF-> FileArtifact`
- `Process -CONNECTED_TO-> NetworkEndpoint`
- `Account -OWNS-> Process`
- `Process -PERSISTED_AS-> PersistenceEntry`
- `Incident -RELATED_TO-> Process/FileArtifact/NetworkEndpoint`
- `Device -PART_OF-> Incident` (optional relation semantics)
Each edge has first/last seen times, evidence event references, confidence,
and immutable identity. `graph_edges` has a uniqueness constraint per
(source,target,relation) and may be updated with newer `last_seen_ms`,
confidence and evidence.

**Bounded investigation**: BFS up to 3 hops, at most 500 traversed edges
per UI request; visited set prevents loops. Ordered traversal prioritizes
recent high-confidence edges. For distinct process lineages, group edges by
boot identity and creation time.

Sample query (one-hop neighbors):
```sql
SELECT e.edge_id,e.relation_type,n.node_id,n.node_type,n.identity_key,
       e.confidence,e.last_seen_ms
FROM graph_edges e
JOIN graph_nodes n ON n.node_id=e.target_node_id
WHERE e.source_node_id=$node
ORDER BY e.last_seen_ms DESC LIMIT 100;
```

## C. K-Means behavior-feature pipeline

The model is a *risk-enrichment signal*, never an autonomous assertion that
a process is malicious. One observation is a **60-second rolling window
for a root-process lineage** (root process and its child processes).

Raw feature schema `lineage-60s-v1`, all nonnegative counts, in this order:
1. process_starts
2. unique_remote_destinations
3. outbound_connection_attempts
4. unsigned_executable_starts
5. persistence_changes
6. blocked_connection_attempts
7. suspicious_child_chains
8. rare_executable_launches

`unsigned` means no valid trusted signing chain according to the configured
Windows signature-verification policy; a missing signature is not sufficient
evidence of malware. `rare_executable` requires a versioned reference cohort
or local established baseline; insufficient baseline means missing, not zero.
`process_starts` excludes event retries/deduplication. Source telemetry
coverage is tracked separately; an incomplete window is unscorable unless
coverage >= 0.90, and every required feature is available.

Training pipeline (isolated, curated/verified benign data only):
1. Partition baseline data by device/cohort and time into disjoint
   training and benign calibration sets. Hold out *separate* evaluation sets
   with realistic benign and malicious behaviors. Do not put replay-duplicate
   lineages in multiple partitions.
2. Compute `caps_j=quantile(train_raw_j, 0.995)`.
3. Transform `x'_j=log(1 + min(x_j,caps_j))`.
4. Fit `StandardScaler` on **training only**:
   `z_j=(x'_j-mean_j)/scale_j`.
5. Train `KMeans(k=8, init="k-means++", n_init=20, random_state=42)`.
   `k=8` is a working candidate; compare 4,8,12 and alternative detectors
   on held-out false positive/detection metrics before adopting.
6. Assign independently collected benign calibration observations to the
   nearest cluster, and calculate within-cluster distance quantile 0.995.
   For underpopulated clusters use a global quantile threshold.
7. Export only feature schema, clip caps, mean, scale, centroids,
   calibration thresholds, metadata; sign detached artifact in approved
   release pipeline. Unsigned training output is **not deployable**.

Inference:
`c = argmin_i ||z - centroid_i||_2`
`d = ||z - centroid_c||_2`
`anomaly_ratio = d / threshold_c`.

If `anomaly_ratio>1`, publish `AnomalyScore` with cluster, ratio,
model ID and coverage. This threshold is a *candidate* and must be evaluated
against held-out normal workloads; no assumed false-positive guarantee.
No model-only blocking or quarantine. Do not train on unlabeled recent
detections without quarantine from poisoning and validation of benign labels.
Add signed fallback model version + rollback on drift.

Python implementation: `ml/train_kmeans.py`.
C# inference reference: `src/Hannibal.Overwatch/KMeansAnomalyScorer.cs`.
Model loader/signing verification is a REQUIRED implementation gate.

## D. Overwatch decision logic

State machine:
`OBSERVE -> INVESTIGATE -> POLICY_EVALUATE -> (ALERT | CONTAIN) -> VERIFY`.
No ML component calls `IContainmentBroker` directly.

Recommended deterministic initial policy (examples, not proven thresholds):
- If target is outside authorized local device scope: DENY.
- If OS/service protected or containment would violate allowlist: ALERT.
- Validated, exact malicious artifact hash from trusted signed feed:
  eligible for quarantine **if** correct file occurrence, stable file
  identity, privilege scope, reputation and rollback rules are satisfied.
- For network endpoint: if severity >=0.85, incident confidence >=0.90,
  and >=2 genuinely independent, validated non-ML evidence sources:
  eligible for **temporary 900-second block** on explicit target,
  after broker validates the IP/port/protocol scope and safety protections.
- Otherwise: alert or observe. Model-only anomaly may influence
  prioritization but not containment.

The source-domain-independent check in sample C# is *necessary but not
sufficient*: production must authenticate provenance and test that two
independent IDs do not originate from the same underlying raw telemetry.
Confidence must be calibrated; numbers above are initial policy proposals.

**Broker security checks** (independently of Overwatch):
- Named-pipe ACL admits only specified service SID, not arbitrary dashboard
  clients; authenticate and bind session to local Windows identity.
- Verify action request authenticity and policy version.
- Re-derive authorization and protected-target exclusions.
- Match process identity (PID + creation time) or file handle/ID + SHA-256,
  rechecking within an OS handle to reduce TOCTOU windows.
- Validate IP address, family, protocol, port and expiry for WFP rules.
- Enforce rate limits, expiration, replay/idempotency, rollback and audit.
- Deny remote/off-device targets and any generic shell/PowerShell command.
- TerminateProcess is disabled in default autonomous policy until
  risk and false-positive tests justify enabling explicit scenarios.
- On broker/Overwatch outage: keep Defender and established Windows rules
  working; defer new dangerous operations and raise incident health events.

## E. Learning/update lifecycle

`CandidateImprovement -> isolated tests -> benchmark -> signed staging ->
verified activation -> production metrics -> rollback if regression`.

Never hot-patch executable services from live ML output. Model artifact must
match schema, signing chain, trusted publisher, content digest, expected
dimensions and release metadata. Staging/activation is transactionally
recorded; keep last-known-good models and policies. Cloud intelligence
is optional, consent-controlled, privacy-filtered and authenticated.

## F. Reference test gates

- Idempotent event inserts and graph joins with FK enforcement.
- Crash/replay and consumer-offset transaction tests.
- Stable process identity under PID reuse, file rename/change race tests.
- Missing telemetry -> `Unscorable`, not zero or benign.
- Model-only anomaly -> ALERT, never containment.
- Cross-device target -> DENY.
- Protected system target -> no automatic containment.
- Exact file hash + signed indicator -> eligible only after broker checks.
- Two independent trustworthy sources -> possible short network block.
- Block expiry/rollback successful after simulated crash.
- Dynamic false-positive/precision/recall measurement on labeled,
  held-out benign and malicious corpora (no benchmark numbers invented).

## G. Evidence limits and reference sources

The user's supplied *Scientific Reports* 2025 research article,
"AI-driven cybersecurity framework for software development based on the
ANN-ISM paradigm", DOI:10.1038/s41598-025-97204-y, motivates combining
learned risk patterns with structured dependency relationships.
It does **not** validate K-Means specifically for consumer antivirus,
the thresholds listed here, or Hannibal's effectiveness.

External engineering documentation:
- .NET releases and support: https://learn.microsoft.com/dotnet/core/releases-and-support
- .NET channels: https://learn.microsoft.com/dotnet/core/extensions/channels
- SQLite .NET concurrency: https://learn.microsoft.com/dotnet/standard/data/sqlite/database-errors
- SQLite PRAGMA: https://sqlite.org/pragma.html
- scikit-learn KMeans: https://scikit-learn.org/stable/modules/generated/sklearn.cluster.KMeans.html
- scikit-learn StandardScaler: https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html
- WFP: https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform
- Protected AV service rules: https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-

## H. What is not implemented in this reference

The code is a functional contract/policy/model/data-schema seed, **not
a complete deployable antivirus product**. Before beta, contractors must
implement sensor collectors, signed artifact verification, local IPC
authentication, production SQLite repository, Windows-specific containment
broker, service installer, GUI, and Windows integration tests. Windows
protected antimalware service status has additional ELAM and certificate
requirements; do not imply that a normal Windows service is tamper-proof.
