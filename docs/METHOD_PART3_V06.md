# SPEC-001 — Hannibal Protocol
## Method Part 3 · Beta implementation v0.6

**Status:** simulation beta. Supersedes v0.5 (`METHOD_PART2_REVIEW_V05.md`) only
where this document says so. Every v0.5 safety rule still applies.

## 1. What changed from v0.5

| Area | v0.5 | v0.6 beta |
| --- | --- | --- |
| Journal and repository | Schema only | `HannibalStore`: SQLite WAL, `synchronous=FULL`, single writer, `BEGIN IMMEDIATE`, idempotent event IDs, consumer offset advanced in the same transaction as the consumer's mutations |
| Trusted ingestion | Requirement | `TrustedIngestor`: registered collectors, per-observation HMAC, channel binding, device binding, freshness, sequence-gap loss accounting, **canonical raw roots** shared across sensors that saw the same event |
| Agents | Contracts | `CoreRuntime` runs all seven agents as one ordered, crash-consistent pipeline |
| Evidence lineage | Tables | Derived findings inherit parent roots recursively; derivation cycles rejected |
| Threat graph | Python BFS | C# port with dependency-explosion control (high-fan-out hubs are not expanded) |
| Policy | Reference engine | Unchanged engine, now fed by verified store data and a signed policy |
| Broker | Not implemented | `SimulationBroker`: authenticated frames, persisted replay guard, independent re-verification, write-ahead intent log, idempotency, rate limits, TTL sweep, crash recovery that fails closed, rollback. **No effector.** |
| Signed artifacts | Requirement | ECDSA P-256 detached signatures over exact bytes; pinned trust root; threshold; expiry; monotonic versions; ML-DSA-65 verification where the OS supports it; Python release tool |
| Isolation ladder | — | New: bounded, TTL-driven, one rung per evaluation |
| Decoys | — | New: planner, renderer, classifier, Windows deployer, hash-checked cleanup |
| UI | — | WPF dashboard, read-only, fed by a pushed snapshot |
| ModelLab | K-Means trainer + evaluator | Detector comparison (k = 4/8/12, IsolationForest, rules-only) with grouped bootstrap; shadow-promotion gate |
| Knowledge graph | — | ATT&CK STIX 2.1 → SQLite builder (pre-v18 and v18 data models), curated rule map |

## 2. Decisions

1. **No NuGet dependency in the tested core.** SQLite is bound directly to
   `winsqlite3.dll` (part of Windows) or the system `libsqlite3`. The decision
   engine, broker and crypto therefore build and test without network access.
2. **The UI has no command channel.** The Core service pushes
   `status/snapshot.json`; the dashboard only reads it. Restore is exposed in
   code (`CoreRuntime.Restore`) but not in the UI until an authenticated UI→Core
   channel is designed. This removes a whole IPC attack surface from the beta.
3. **Calibration is a signed attestation.** A network action needs
   `calibration_attested: true` and the SHA-256 of the evaluation report in the
   signed policy bundle. The beta bundle attests nothing, so network actions are
   never proposed, even as simulations. Quarantine of an exact signed-indicator
   match does not depend on calibration (v0.5 rule).
4. **Ladder semantics.** Behavioural decisions climb one rung per evaluation.
   Only an exact signed-indicator match may enter *Hold* directly. A rung steps
   down one level when its TTL ends without renewed support.
5. **A process is never a containment target.** Automatic termination stays
   disabled (v0.5). Incidents without a file or endpoint target are treated as protected.
6. **Crash recovery never re-applies.** An intent without a recorded effect
   becomes `FAILED_ON_CRASH`. For a future WFP effector, dynamic sessions remove
   filters when the broker dies; reconciliation must then either re-apply
   unexpired blocks deliberately or report them expired. That code belongs to
   the enforcing build.
7. **Decoy names stay private.** The world-readable snapshot names a decoy by ID and folder only.
8. **Decoys are placed by the elevated installer, not the service.** The Core
   service's virtual account cannot write into user profiles and should not
   be able to. `install.ps1 -DeployDecoys` places them; the service only reads
   the manifest; uninstall removes only unchanged decoys.
9. **The language model is deferred.** Explanations are deterministic templates
   bound to evidence roots. A local model may later *rephrase* the claim list,
   with no tool or action access. Endpoint strings are sanitised as untrusted
   data (control and bidi characters stripped, length-capped, quoted). This
   follows the CISA et al. (Dec 2025) guidance that LLMs should not make safety
   decisions in operational environments.

## 3. Research recommendations: disposition

| Rank | Recommendation | Disposition in the beta |
| --- | --- | --- |
| 1 | Canary files and decoy credentials | **Implemented** (files and credential exports). Registry-value decoys: schema ready, not deployed |
| 2 | Two-channel, disjoint-root corroboration | **Implemented and tested** |
| 3 | Signed bundles with TUF-style protections | **Implemented** (pinned keys, threshold, expiry, rollback). Full TUF roles: not yet |
| 4 | Progressive isolation via dynamic WFP, TTL ≤ 900 s | **Ladder implemented; actions simulated.** WFP effector deferred to the enforcing pilot |
| 5 | Scipio loop: coverage, Atomic tests, shadow gate | **Implemented** (axis coverage, comparison, shadow gate); Atomic runs are in the test plan |
| 6 | K-Means as a ranker only | **Kept**: shadow-only unless a signed non-candidate model is installed; even then triage only |
| 7 | KG-grounded explanations | **KG builder and evidence-bound templates implemented**; no language model |
| 8 | Local decoy listeners / tarpit | **Deferred** (port conflicts, denial-of-service risk) |
| — | Kernel driver, ETW Threat-Intelligence, WSC registration | **Deferred**: require MVI membership |
| ✗ | Hack-back or any off-device action | **Excluded permanently** |

## 4. Trust chain as built

`ETW / Sysmon` → `ICollectorSource` (HMAC with a per-collector key) →
`TrustedIngestor` (canonical raw root) → `security_events` + `event_roots` →
detection findings (`evidence_records`, `evidence_roots`) → derived findings
(`evidence_derivations`) → `SafeOverwatchPolicyEngine` → `IsolationLadder` →
`BrokerClient` (HMAC frame, counter, nonce, 15 s lifetime) → named pipe (ACL:
SYSTEM + `NT SERVICE\HannibalCore`, NETWORK denied, first-instance) →
`SimulationBroker` (re-verification against its own bundles) → `broker_intents`.

## 5. Security model and known gaps

- **Local administrator = advanced adversary.** ACLs and hash chains make
  tampering harder and evident; they do not prevent it.
- **Collector authenticity is in-process.** The collectors run inside the Core
  service. The HMAC protects the ingestion contract and prepares for
  out-of-process collectors; it is not a defence against a compromised Core process.
- **PPID spoofing.** The reported parent is recorded (`reported_ppid`); the
  creating process is not yet captured.
- **Catalog signatures.** `Authenticode.Status` reports catalog-signed system
  files as `unknown`, never `unsigned`. Catalog lookup is pending.
- **Session key at rest.** A random per-install key in an ACL'd file. A TPM-backed
  key (Microsoft Platform Crypto Provider) is planned.
- **Boot ID.** Derived from the boot time to the second. Verify stability across sleep/hibernate.
- **Snapshot.** Readable by local users; contains device ID, endpoint keys and folder names.

## 6. Not implemented (stated plainly)

Network-blocking, quarantine or termination effectors · WFP net-event
collector (the `os-denied-connections` axis reports *unwatched*) · Security
Audit event-log collector · Sysmon collector · registry decoys · decoy listeners ·
catalog signature verification · TPM key storage · authenticated UI→Core
channel and restore button · local language model · cloud intelligence ·
Windows build of the ETW collectors, services and dashboard (written, not
compiled) · real-world evaluation data · code signing.
