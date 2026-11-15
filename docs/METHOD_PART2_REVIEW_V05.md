# SPEC-001 — Hannibal Protocol
## Method Part 2 · Security-strengthened revision v0.5

**Status:** engineering design and non-production reference code. Windows 11;
local-first; opt-in cloud; restricted defensive containment. This document
revises and supersedes the v0.4 Method Part 2 where its rules conflict.

### 1. Findings and disposition

| Finding | Severity | v0.5 correction |
| --- | --- | --- |
| Any provenance-valid Signature finding with a SHA256-bearing file could enable quarantine without exact signed-indicator match | Critical | Exact SHA256 and file-identity match, signed indicator bundle, time-validity, broker recheck |
| Graph and raw telemetry could be counted independently even if graph derived from same raw event | Critical | Evidence roots and derivation lineage; graph findings excluded from network-action quorum |
| Apparent confidence numbers lacked calibration and data-quality gates | High | Telemetry health, calibration gates, freshness, calibrated precision/recall evaluation |
| 99.5% clipping could hide very large feature spikes | High | Surface `out_of_training_support` and exceeded cap count, never silently treat normal |
| K-Means 8 clusters and 0.995 quantiles were not justified | High | Compare k=4/8/12 and IsolationForest/rules-only, bootstrap by device and time cohort |
| Process graph edges conflated summary relationships with event instances | High | `graph_edge_observations` with time and evidence IDs; time-respecting traversal |
| Feature schema included detection-derived 'suspicious' counts | Medium | v2 uses raw telemetry and versioned local baselines instead |
| Retrospective windows could be treated as independent tests | Medium | Split by device, lineage, time and malware campaign; group windows into incidents |
| Recursive learning could incorporate attacker-generated observations | High | Quarantine data curation, poisoning checks, staged model activation; no automatic privileged code changes |

### 2. K-Means evidence strength

**Role**: behavioral anomaly *ranking* only, not malware classification.

The v2 raw feature vector for each 60-second process-lineage window, exactly in
`ml/features.py` order, is:

1. `process_starts`: observed child process launches, deduplicated.
2. `unique_remote_destinations`: distinct IP endpoints contacted.
3. `outbound_connection_attempts`: allowed/attempted external connection count.
4. `unsigned_executable_starts`: launches whose signature verification definitively failed or no trusted signer was present; distinguish missing signer from invalid chain in raw evidence.
5. `persistence_changes`: observed creation/modification of startup/persistence configuration.
6. `os_denied_connection_attempts`: denied connections from OS controls, EXCLUDING Hannibal-originated blocks.
7. `max_process_lineage_depth`: maximum parent-child depth observed from stable process identity.
8. `new_executable_hashes_30d`: SHA256 artifacts first seen in the device's prior 30-day reference baseline; no complete baseline => unavailable.

All values are finite nonnegative numerical features. Missing collection is not
zero, and essential missing features render the window unscorable. `coverage`
is separately verified against sensor heartbeat and dropped-event counters.

Preprocessing and scoring: the existing reproducible `log1p`, train-only
winsorization, `StandardScaler`, `KMeans(n_init=20, random_state=42)`, separate
benign calibration, nearest-centroid distance and ratio `d/tau` are retained.
Explicitly emit `exceeded_training_caps` whenever inference exceeds a trained
feature cap. Such observations require separate review: clipping can otherwise
turn an extremely large anomaly into a typical upper-capped value.

**Selection**:
- Candidate k = 4, 8, 12; compare using held-out labeled datasets.
- Required baselines: rule-only threat detection and IsolationForest novelty
  detection, plus the same engine with K-Means disabled.
- Primary metrics: average precision (PR), recall at operating threshold,
  false-positive alert episodes per endpoint-day, severity-weighted false
  containment, and time to first useful detection.
- Evaluate unseen device cohorts, benign software installation/update spikes,
  games, developer tools, low-end machines, malicious test behaviors, and
  unseen malware families, separately.
- Confidence intervals: grouped bootstrap by device/incident, not by highly
  correlated overlapping 60-second windows.
- Group windows from one incident with alert suppression and bounded
  cooldowns. A 0.5% *window* alert rate does not imply a practical endpoint
  false-alert burden.
- Release gates (proposed, must confirm with real evaluation): false
  containment = 0 in pilot; benign false alert episodes <= 1 per
  endpoint-week; no material recall regression against rule-only baseline.
  A zero observed false-containment rate is not a guarantee of safety.
- New K-Means variants remain candidates until a signed model passes shadow
  mode, stage gates, and rollback tests. Model drift is monitored by
  out-of-support fraction and distribution shift across device cohorts.

### 3. Provenance-correct threat graph

Two-level representation:
1. **Entity graph summary:** typed nodes and summarized edges in
   `graph_nodes`/`graph_edges`.
2. **Observation layer:** actual events in
   `graph_edge_observations` linked to evidence IDs and raw root observation
   IDs through `evidence_records` and `evidence_roots`.

Typed IDs:
- Process = `(device, boot-id, pid, creation-timestamp, image-file-id)`.
- File occurrence = `(device, volume-id, file-id, observation epoch)`.
- File artifact = `SHA256(bytes)`; do not use path as identity.
- Network endpoint = `(protocol, family, address, port, scope)`; reverse DNS
  is annotative metadata, not a stable identity.
- Persistence entry = `(device, registry hive/path/value or scheduled task GUID)`.
- Incident = generated ID and explicit membership edges.

Legal relationships enforce source and target types in graph building:
`Process -SPAWNED-> Process`,
`Process -EXECUTED-> FileOccurrence`,
`FileOccurrence -INSTANCE_OF-> FileArtifact`,
`Process -CONNECTED_TO-> NetworkEndpoint`,
`Account -OWNS-> Process`,
`Process -PERSISTED_AS-> PersistenceEntry`.
Incident membership is separate from fact relationships. Reject type-mismatched
edges before DB insertion.

**Investigation algorithm** (`graph/investigate.py`):
- Directed breadth-first search from an entity, depth <= 3; work budget
  <= 500 inspected edges; same-authorized-device only.
- Match actual observation times in a bounded incident window;
  along a candidate chain, times must be nondecreasing and successive
  observations no farther than a configurable limit (initial 15 minutes).
- Require nonempty evidence roots and legal typed relations.
- Suppress cycles and return candidate paths as *hypotheses*, with associated
  raw evidence and time bounds. A path is never proof of intent or automatic
  independent corroboration.
- A slower attack may require a separate long-duration investigative view
  that explicitly reports increased uncertainty; do not quietly expand the
  automatic response window.

Graph-derived scores can increase investigation priority and user
explainability, but **MUST NOT count as independent corroboration** of the raw
observations from which they were computed. Map verified data components to
current MITRE ATT&CK terms; avoid assuming historical ATT&CK 'data sources'
are maintained as new catalog entries.

### 4. Overwatch evidence independence and decision safety

**Required trust chain**:
`OS observation -> authenticated collector -> trusted ingestion journal ->
  immutable raw root event ID -> derived finding with explicit root references ->
  incident hypothesis -> policy evaluator -> privileged broker re-verification`.

Only the trusted ingestion verifier can mark a source verified. Agent-supplied
boolean fields are merely claims. Derived models (graph and ML) cannot assign
their own trust level. Prevent parent cycles in `evidence_derivations`.

**Corroboration rule for network action**:
- At least two credible *raw-observation* findings.
- Distinct nonempty `capture_channel` IDs from verified collectors.
- Disjoint canonical `raw_root_event_ids` sets (recursively resolved from the
  derivation graph).
- Both facts match the SAME target identity and device, are fresh (initial
  <= 120 seconds) and have acceptable collection health.
- Ignore graph, ML anomaly and exposure-only findings for this quorum.
- Enforce policy signature and calibrated confidence conditions. Initial
  severity/confidence thresholds of .85/.90 are provisional.
- For duplicate observations across sensors of one event, the ingestion
  system must canonicalize a shared root ID; "different channels" alone
  cannot certify independence.
- If provenance, time, scope, calibration, or sensor integrity is uncertain,
  ALERT and do not initiate automatic new containment.

**File quarantine rule**:
- Match `target.FileSha256` to both *observed file SHA256* and exact malicious
  hash in a currently valid, verified, signed indicator bundle.
- Match stable file occurrence identity and device.
- Confirm no revocation and an in-scope action.
- The privileged broker reopens the file by a stable identifier, hashes the
  same handle, checks signer/protected file policy, refuses OS/system files,
  performs an atomic/quasi-atomic restricted move when possible, and records
  a restore token. If handle binding cannot be guaranteed, deny.
- Quarantine never automatically deletes files. Signed indicator match is not
  sufficient to bypass protected target and user-data recovery rules.

**Network block rule**:
- Non-system, fully qualified local endpoint tuple; allowlisting DNS, captive
  portal, local gateway, emergency connectivity and critical OS services must
  be designed/tested, not assumed.
- Restrict rule to requested device and endpoint (protocol, IP, port, direction),
  TTL initially <= 900 s; idempotent action token and automatic cleanup.
- Broker verifies time-bound signed policy/decision, local scope, stable target,
  authorization and all protected-target exclusions. No generic shell runner.
- Enable first in **simulation** mode, then opt-in guarded pilot.
- Default automatic process termination is DISABLED pending stronger evidence.

**State machine**:
`OBSERVE -> TRIAGE -> VERIFY_EVIDENCE -> EVALUATE_POLICY ->
 (MONITOR | ALERT | SIMULATED_ACTION | AUTHORIZED_CONTAINMENT)
 -> VERIFY_EFFECT -> (RECOVER | CLOSE | REASSESS)`
All transitions audit decision ID, policy version, root evidence IDs,
unavailable telemetry, broker outcome and rollback. A model-only anomaly
may trigger `TRIAGE` but never `AUTHORIZED_CONTAINMENT`.

**Failure behavior**:
- Missing telemetry, unverified policy, stale data, invalid numbers,
  incompatible schema, cloud outage: decline new risky actions and raise a
  health condition; existing Defender protections continue.
- Overwatch/broker outage: preserve existing validated blocks with configured
  expiration, do not issue new privileged instructions.
- Treat a compromised local privileged account as an advanced adversary:
  normal SQLite ACLs alone are not tamper resistance. Signed external audit
  receipts are an optional later hardening, not proof of tamper immunity.
- Provenance checks do not by themselves prevent a malicious collector; trust
  establishment and intrusion testing remain necessary.

### 5. Data schema and contracts

Run `db/001_initial.sql` followed by
`db/002_evidence_provenance.sql`, creating:
`evidence_records`, `evidence_roots`, `evidence_derivations`,
`malicious_file_indicators`, `graph_edge_observations`,
`attack_hypotheses`, `policy_decision_evidence`,
`model_evaluation_reports`.

New C# reference:
- `src/Hannibal.Overwatch/SafetyContracts.cs` typed verified evidence and
  signed indicator match envelopes.
- `src/Hannibal.Overwatch/SafeOverwatchPolicyEngine.cs` pure reference policy,
  no privileged operations. THIS supersedes `OverwatchPolicyEngine.cs` in
  v0.4 and requires C# compilation/verification on Windows 11.
- `tests/Hannibal.SmokeTests/Program.cs` regression cases for hash mismatch,
  derived evidence re-use, mixed sensor independence, graph exclusions,
  protected targets, missing telemetry and stale evidence.

The broker MUST reject self-asserted `TrustedIngestVerified` or
`SignatureVerified` values over IPC. It must validate a trusted, authenticated
issuer and re-derive cryptographic source validity from protected storage.

### 6. Recursive learning deployment gates

1. Collect training candidates under privacy and legal authorization.
2. Filter/label benign windows with independent validation; quarantine
   attacker-controlled examples and suspected poisoning.
3. Split by device, time, process lineage, campaign/family.
4. Compare candidates against incumbent on fixed and recent held-out data.
5. Run shadow mode (candidate scores published, no action authority).
6. Validate minimum measured gain AND maximum tolerated regressions.
7. Sign immutable artifact in independent release pipeline.
8. Deploy small staged cohort, instrument errors, false-alert episodes,
   drift and update integrity. Roll back to last-known-good on degradation.
9. Never automatically rewrite executable/driver/broker authorization code.

### 7. Validation matrix (no claims of real protection yet)

| Test | Expected |
| --- | --- |
| Exact malicious hash mismatched against target | No quarantine |
| Hash match but unsigned/revoked indicator | No quarantine |
| Graph finding derived from same ETW event | No extra corroboration |
| Two different source IDs with same raw root | No network block |
| Different authenticated collectors and raw roots | May qualify for policy stage, broker still rechecks |
| ML anomaly only | Alert/triage, never block |
| Protected Windows process/file | No automatic containment |
| Cross-device/cross-network target | Deny |
| Missing/late telemetry | Alert, decline new risky action |
| Invalid or uncalibrated confidence | Alert, decline new risky action |
| Excessively large clipped ML feature | Disclosed out-of-training-support |
| Out-of-order or time-gap graph path | Not considered a causal chain |
| Model drift / poisoning / unsigned model | No model activation |
| Broker crash during block/quarantine | Idempotent recovery/rollback |

### 8. Sources and constraints

The supplied article by Khan et al., *Scientific Reports* (2025),
DOI 10.1038/s41598-025-97204-y, supports research into combining learned
patterns with structural risk relationships, while acknowledging simulated
environments, data quality, generalization and false-positive risks. It
does NOT empirically validate Hannibal's K-Means, graph causal inference,
or Overwatch thresholds.

Relevant engineering references:
- scikit-learn clustering: https://scikit-learn.org/stable/modules/clustering.html
- scikit-learn novelty detection: https://scikit-learn.org/stable/modules/outlier_detection.html
- scikit-learn precision/recall: https://scikit-learn.org/stable/auto_examples/model_selection/plot_precision_recall.html
- MITRE ATT&CK data components: https://attack.mitre.org/datacomponents/
- MITRE D3FEND: https://d3fend.mitre.org/
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST AI RMF measurement: https://airc.nist.gov/airmf-resources/playbook/measure/
- SQLite WAL: https://www.sqlite.org/wal.html

**Not implemented:** signed trust verifier, authenticated collector, safe
Windows broker, live system event ingestion, GUI, real-world endpoint tests,
Windows C# compilation, broker crash recovery. These are implementation
requirements rather than working beta capabilities.
