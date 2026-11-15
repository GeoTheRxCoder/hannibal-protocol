using System.Text.Json;
using Hannibal.Contracts;
using Hannibal.Core.Analysis;
using Hannibal.Core.Deception;
using Hannibal.Core.Graph;
using Hannibal.Core.Ingest;
using Hannibal.Core.Ipc;
using Hannibal.Core.Maneuver;
using Hannibal.Core.Relay;
using Hannibal.Core.Restoration;
using Hannibal.Core.Ribat;
using Hannibal.Core.Storage;
using Hannibal.Overwatch;

namespace Hannibal.Core.Agents;

public sealed record CoreOptions(string DeviceId, OperatingMode Mode = OperatingMode.Simulation, string Environment = "SIMULATION ENVIRONMENT");

public sealed record ProcInfo(string Key, string? ParentKey, string RootKey, int Depth, string ImageName, string SignerStatus);

/// <summary>
/// Hosts the seven logical agents as one ordered, crash-consistent pipeline:
///
///   Sentry -> Reconnaissance -> ThreatDetection -> TacticalML ->
///   ThreatAnalysis -> Overwatch -> CounterOffensive (local countermeasures)
///
/// Each journal entry is processed and its consumer offset advanced inside a
/// single transaction. Only Overwatch decides; only the broker acts; in this
/// beta the broker only simulates. "CounterOffensive" means local, reversible
/// countermeasures on this device - deception and the isolation ladder. There
/// is no off-device action of any kind.
/// </summary>
public sealed class CoreRuntime
{
    public const string Consumer = "core-pipeline";
    private static readonly HashSet<string> Launchers = new(StringComparer.OrdinalIgnoreCase)
        { "explorer.exe", "services.exe", "svchost.exe", "winlogon.exe", "userinit.exe", "sihost.exe", "wininit.exe" };

    private static readonly Dictionary<string, double> RuleWeight = new(StringComparer.Ordinal)
    {
        ["R-CANARY"] = .90, ["R-INDICATOR"] = .99, ["R-PERSIST-UNTRUSTED"] = .35,
        ["R-LINEAGE-EGRESS"] = .30, ["R-ML-ANOMALY"] = .20, ["R-GRAPH-PATH"] = 0
    };

    private readonly HannibalStore _store;
    private readonly TrustedIngestor _ingestor;
    private readonly BundleIntake _intake;
    private readonly BrokerClient _broker;
    private readonly ProtectedTargets _protected;
    private readonly CoreOptions _opt;
    private readonly Func<long> _clock;
    private readonly SafeOverwatchPolicyEngine _policy = new();

    private readonly Dictionary<string, ProcInfo> _procs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _detail = new(StringComparer.Ordinal);      // evidence id -> sanitized detail
    private readonly Dictionary<string, string> _targetPath = new(StringComparer.Ordinal);  // file key -> path
    private readonly Dictionary<string, (DecisionKind Kind, string Reason, string DecisionId)> _lastDecision = new(StringComparer.Ordinal);
    private readonly Dictionary<(string Root, long Start), Window> _windows = new();
    private readonly Dictionary<AgentId, long> _agentSeq = new();
    private readonly HashSet<string> _touched = new(StringComparer.Ordinal);

    public LoadedModel? Model { get; set; }

    public CoreRuntime(HannibalStore store, TrustedIngestor ingestor, BundleIntake intake, BrokerClient broker,
        ProtectedTargets protectedTargets, CoreOptions options, Func<long> clock)
    {
        if (options.Mode != OperatingMode.Simulation)
            throw new NotSupportedException("Enforcing mode is not available in the beta. The broker has no effector.");
        _store = store; _ingestor = ingestor; _intake = intake; _broker = broker;
        _protected = protectedTargets; _opt = options; _clock = clock;
        foreach (var a in Enum.GetValues<AgentId>()) _agentSeq[a] = 0;
        store.Audit.Append(clock(), "CORE_START", JsonSerializer.Serialize(new { mode = options.Mode.ToString(), options.DeviceId }));
    }

    // ---------------------------------------------------------------- pump --

    /// <summary>Processes pending journal entries. Returns how many were consumed.</summary>
    public int Pump(int maxEvents = 500)
    {
        long now = _clock();
        var entries = _store.ReadAfter(_store.GetOffset(Consumer), maxEvents);
        foreach (var e in entries)
        {
            _store.Transact(() =>
            {
                Reconnaissance(e);
                ThreatDetection(e, now);
                TacticalMlAccumulate(e);
                _store.SetOffset(Consumer, e.Seq, now);
            });
            foreach (var a in new[] { AgentId.Sentry, AgentId.Reconnaissance, AgentId.ThreatDetection, AgentId.TacticalML })
                _agentSeq[a] = e.Seq;
        }
        Evaluate(_touched.ToArray(), now);
        _touched.Clear();
        return entries.Count;
    }

    /// <summary>Periodic duties: close ML windows, re-evaluate open incidents (TTL and staleness), health.</summary>
    public void Tick()
    {
        long now = _clock();
        TacticalMlClose(now);
        _store.Db.Execute(Sql.ExpireContainment, now, now);
        _store.Db.Execute(Sql.ReopenUncontained, now);
        var open = _store.ListIncidents(200).Where(i => i.Status is "open" or "investigating" or "contained").Select(i => i.IncidentId).ToArray();
        Evaluate(open.Concat(_touched).Distinct().ToArray(), now);
        _touched.Clear();
        AxisCoverage.Refresh(_store, _ingestor, _opt.DeviceId, now);
        bool telemetry = _ingestor.EssentialTelemetryHealthy(now);
        foreach (var a in Enum.GetValues<AgentId>())
        {
            string health = a switch
            {
                AgentId.Sentry => telemetry ? "healthy" : "degraded",
                AgentId.TacticalML => Model is null ? "degraded" : "healthy",
                AgentId.Overwatch => _intake.PolicyVerified ? "healthy" : "degraded",
                _ => "healthy"
            };
            string detail = a switch
            {
                AgentId.Sentry => telemetry ? "Essential channels healthy" : "An essential capture channel is offline or losing events",
                AgentId.TacticalML => Model is null ? "No signed model loaded; ranking unavailable" : Model.ShadowOnly ? "Shadow model: scores published, no weight" : "Signed model loaded; triage ranking only",
                AgentId.Overwatch => _intake.PolicyVerified ? "Signed policy verified" : "No verified policy; new actions declined",
                AgentId.CounterOffensive => "Local countermeasures only; all actions simulated",
                _ => "Running"
            };
            _store.Heartbeat(a.ToString(), now, _agentSeq[a], health, JsonSerializer.Serialize(new { detail }));
        }
    }

    // ------------------------------------------------------ Reconnaissance --

    private void Reconnaissance(JournalEntry e)
    {
        string dev = e.DeviceId;
        void Edge(string srcType, string srcKey, string rel, string dstType, string dstKey)
        {
            if (!Investigator.IsLegal(srcType, rel, dstType)) return; // type-mismatched edges never reach the DB
            var s = _store.UpsertNode(dev, srcType, srcKey, e.ObservedMs);
            var d = _store.UpsertNode(dev, dstType, dstKey, e.ObservedMs);
            _store.UpsertEdgeObservation(s, d, rel, e.ObservedMs, .95, e.Seq, e.RootEventId, dev);
        }

        switch (e.Kind)
        {
            case ObservationKinds.ProcessStart:
            {
                string parent = e.Field("parent_key");
                string image = e.Field("image_name");
                _procs.TryGetValue(parent, out var p);
                bool newRoot = p is null || Launchers.Contains(p.ImageName);
                _procs[e.SubjectKey] = new ProcInfo(e.SubjectKey, parent.Length > 0 ? parent : null,
                    newRoot ? e.SubjectKey : p!.RootKey, newRoot ? 0 : p!.Depth + 1, image, e.Field("signer_status"));
                _store.UpsertNode(dev, "Process", e.SubjectKey, e.ObservedMs);
                if (parent.Length > 0) Edge("Process", parent, "SPAWNED", "Process", e.SubjectKey);
                string fileKey = e.Field("image_file_key"), sha = e.Field("image_sha256");
                if (fileKey.Length > 0)
                {
                    Edge("Process", e.SubjectKey, "EXECUTED", "FileOccurrence", fileKey);
                    if (Identity.IdentityKeys.IsSha256(sha))
                        Edge("FileOccurrence", fileKey, "INSTANCE_OF", "FileArtifact", Identity.IdentityKeys.FileArtifact(sha));
                }
                if (e.Field("account_sid").Length > 0) Edge("Account", e.Field("account_sid"), "OWNS", "Process", e.SubjectKey);
                break;
            }
            case ObservationKinds.NetConnect when e.Field("process_key").Length > 0:
                Edge("Process", e.Field("process_key"), "CONNECTED_TO", "NetworkEndpoint", e.SubjectKey);
                break;
            case ObservationKinds.PersistChange when e.Field("process_key").Length > 0:
                Edge("Process", e.Field("process_key"), "PERSISTED_AS", "PersistenceEntry", e.SubjectKey);
                break;
        }
    }

    /// <summary>
    /// Decoy file names stay inside the ACL-restricted core database. The status
    /// snapshot is readable by local users - and so by user-mode malware - so it
    /// names a decoy by id and parent folder only.
    /// </summary>
    private static string FolderName(string location)
    {
        var parts = location.Replace('/', '\\').TrimEnd('\\').Split('\\');
        return parts.Length >= 2 ? parts[^2] : "unknown folder";
    }

    private string RootOf(string processKey) =>
        _procs.TryGetValue(processKey, out var p) ? p.RootKey : processKey.Length > 0 ? processKey : "unattributed";

    // ----------------------------------------------------- ThreatDetection --

    private void ThreatDetection(JournalEntry e, long now)
    {
        string actor = e.Field("process_key");
        _procs.TryGetValue(actor, out var proc);
        string corr = RootOf(actor);

        void Finding(string rule, string family, string subject, double confidence, string detail)
        {
            var incident = _store.OpenIncident(e.DeviceId, corr, now);
            var id = HannibalStore.StableId("ev", rule, e.RootEventId, subject);
            // Everything in the journal passed the trusted ingestor, so a raw finding built from it is 'verified'.
            if (_store.AddEvidence(id, incident, e.Seq, e.DeviceId, subject, family, e.CaptureChannel,
                    "ThreatDetection/" + rule, e.ObservedMs, "verified", confidence, [e.RootEventId]))
                _detail[id] = detail;
            _touched.Add(incident);
            _agentSeq[AgentId.ThreatDetection] = e.Seq;
        }

        if (e.Kind is ObservationKinds.FileRead or ObservationKinds.FileWrite or ObservationKinds.FileRename
            or ObservationKinds.FileDelete or ObservationKinds.DecoyTouch)
        {
            string path = e.Field("path");
            var canary = _store.ListCanaries(e.DeviceId).FirstOrDefault(c =>
                c.Status is "deployed" or "tripped" &&
                (c.Location.Equals(path, StringComparison.OrdinalIgnoreCase) || c.FileIdentityKey == e.SubjectKey));
            if (canary is not null)
            {
                var v = CanaryClassifier.Classify(e.Kind, proc?.ImageName ?? "", proc?.SignerStatus ?? "unknown");
                if (v.IsTripwire)
                {
                    _store.MarkCanary(canary.CanaryId, "tripped", now);
                    Finding("R-CANARY", "Behavior", corr, v.Confidence,
                        $"{v.Reason}: decoy {canary.CanaryId[..10]} in {Explain.Untrusted(FolderName(canary.Location))} via {e.Kind} by {Explain.Untrusted(proc?.ImageName ?? "unknown process")}");
                }
            }
        }

        if (e.Kind == ObservationKinds.FileHash)
        {
            string sha = e.Field("sha256").ToLowerInvariant();
            bool hit = _store.IndicatorsBySha(sha).Any(r => (string)r[4]! == "verified" && (long)r[3]! > now);
            if (hit)
            {
                if (corr == "unattributed") corr = e.SubjectKey;
                Finding("R-INDICATOR", "Signature", e.SubjectKey, .99,
                    $"File {Explain.Untrusted(e.Field("path"))} has a SHA-256 listed in a signed indicator bundle");
                var incident = _store.OpenIncident(e.DeviceId, corr, now);
                _store.SetIncidentTarget(incident, "FileOccurrence", e.SubjectKey, sha);
                _targetPath[e.SubjectKey] = e.Field("path");
            }
        }

        // Supporting rules only add to an incident that already exists for the lineage.
        bool hasIncident = corr != "unattributed" && _store.Db.Scalar(Sql.IncidentByKey, e.DeviceId, corr) is not null;
        if (hasIncident && e.Kind == ObservationKinds.PersistChange && proc is not null && proc.SignerStatus != "trusted")
            Finding("R-PERSIST-UNTRUSTED", "Behavior", corr, .60,
                $"Persistence entry {Explain.Untrusted(e.SubjectKey)} changed by a process without a trusted signature");
        if (hasIncident && e.Kind == ObservationKinds.NetConnect)
            Finding("R-LINEAGE-EGRESS", "Behavior", e.SubjectKey, .85,
                $"Outbound connection to {Explain.Untrusted(e.SubjectKey)} by a lineage under investigation");
    }

    // ---------------------------------------------------------- TacticalML --

    private sealed class Window
    {
        public int ProcessStarts, Connects, Unsigned, Persist, OsDenied, MaxDepth, NewHashes;
        public readonly HashSet<string> Destinations = new(StringComparer.Ordinal);
        public readonly HashSet<string> Roots = new(StringComparer.Ordinal);
    }

    private void TacticalMlAccumulate(JournalEntry e)
    {
        string actor = e.Kind == ObservationKinds.ProcessStart ? e.SubjectKey : e.Field("process_key");
        if (actor.Length == 0) return;
        var key = (RootOf(actor), e.ObservedMs / 60_000 * 60_000);
        if (!_windows.TryGetValue(key, out var w)) _windows[key] = w = new Window();
        if (w.Roots.Count < 64) w.Roots.Add(e.RootEventId);
        switch (e.Kind)
        {
            case ObservationKinds.ProcessStart:
                w.ProcessStarts++;
                if (e.Field("signer_status") is "unsigned" or "invalid") w.Unsigned++;
                if (_procs.TryGetValue(e.SubjectKey, out var p)) w.MaxDepth = Math.Max(w.MaxDepth, p.Depth);
                string sha = e.Field("image_sha256");
                if (Identity.IdentityKeys.IsSha256(sha) && _store.TouchHash(e.DeviceId, sha, e.ObservedMs) == e.ObservedMs)
                    w.NewHashes++;
                break;
            case ObservationKinds.NetConnect: w.Connects++; w.Destinations.Add(e.SubjectKey); break;
            case ObservationKinds.NetDenied when e.Field("blocked_by") == "os": w.OsDenied++; break; // Hannibal's own blocks are excluded
            case ObservationKinds.PersistChange: w.Persist++; break;
        }
    }

    private void TacticalMlClose(long now)
    {
        const long ThirtyDays = 30L * 24 * 3600 * 1000;
        bool baselineComplete = now - _store.BaselineStartedMs(_opt.DeviceId, now) >= ThirtyDays;
        double coverage = _ingestor.Coverage(now);
        foreach (var ((root, start), w) in _windows.Where(kv => kv.Key.Start + 60_000 <= now).ToArray())
        {
            _windows.Remove((root, start));
            // Feature order is fixed by ml/features.py (lineage-60s-v2).
            double[] x = [w.ProcessStarts, w.Destinations.Count, w.Connects, w.Unsigned, w.Persist, w.OsDenied, w.MaxDepth, w.NewHashes];
            string[] unavailable = baselineComplete ? [] : ["new_executable_hashes_30d"];
            double? ratio = null;
            ModelScore? score = null;
            if (Model is not null && unavailable.Length == 0)
            {
                score = Model.Scorer.Score(x, coverage);
                if (score.IsScorable) ratio = score.AnomalyRatio;
            }
            var id = HannibalStore.StableId("fw", _opt.DeviceId, root, start.ToString());
            _store.SaveFeatureWindow(id, _opt.DeviceId, root, start, start + 60_000, SignedModelLoader.ExpectedSchema,
                JsonSerializer.Serialize(new { features = x, unavailable, exceeded_training_caps = score?.ExceededTrainingCaps ?? 0,
                    shadow = Model?.ShadowOnly }), coverage, ratio);

            // A shadow model publishes scores only. A non-shadow model may open TRIAGE - nothing more.
            if (score is { IsScorable: true } && Model is { ShadowOnly: false } && (ratio > 1 || score.ExceededTrainingCaps > 0))
            {
                var incident = _store.OpenIncident(_opt.DeviceId, root, now);
                _store.AddEvidence(HannibalStore.StableId("ev", "R-ML-ANOMALY", id), incident, null, _opt.DeviceId, root,
                    "MlAnomaly", "derived-ml", "TacticalML/R-ML-ANOMALY", start + 60_000, "unverified",
                    Math.Min(.5, 0.25 * (ratio ?? 1)), w.Roots);
                _touched.Add(incident);
            }
        }
    }

    // ------------------------------------- ThreatAnalysis + Overwatch + CM --

    private void Evaluate(string[] incidentIds, long now)
    {
        foreach (var id in incidentIds)
        {
            var inc = _store.GetIncident(id);
            if (inc is null) continue;
            _store.Transact(() =>
            {
                var evidence = ThreatAnalysis(inc, now);
                inc = _store.GetIncident(id)!;
                var decision = OverwatchDecide(inc, evidence, now, out var decisionId, out bool isNew);
                LocalCountermeasures(inc, decision, decisionId, now);
                if (isNew) _agentSeq[AgentId.Overwatch] = _store.GetOffset(Consumer);
            });
            _agentSeq[AgentId.ThreatAnalysis] = _agentSeq[AgentId.CounterOffensive] = _store.GetOffset(Consumer);
        }
    }

    private static string Rule(EvidenceRow e) => e.ProducerId[(e.ProducerId.IndexOf('/') + 1)..];

    private IReadOnlyList<EvidenceRow> ThreatAnalysis(IncidentRow inc, long now)
    {
        var evidence = _store.GetEvidence(inc.IncidentId);
        var raw = evidence.Where(e => e.TrustStatus == "verified" && e.Family is "Behavior" or "Signature" or "Reputation").ToList();

        // Graph hypothesis: derived from the same raw findings, so it shares their roots by construction.
        if (raw.Count > 0 && evidence.All(e => e.Family != "Graph"))
        {
            var obs = _store.LoadEdgeObservations(inc.DeviceId, Math.Max(0, inc.OpenedMs - 900_000), now);
            var paths = Investigator.Investigate(inc.CorrelationKey, inc.DeviceId, obs, Math.Max(0, inc.OpenedMs - 900_000), now);
            if (paths.Count > 0)
            {
                _store.AddEvidence(HannibalStore.StableId("ev", "R-GRAPH-PATH", inc.IncidentId), inc.IncidentId, null,
                    inc.DeviceId, inc.CorrelationKey, "Graph", "derived-graph", "ThreatAnalysis/R-GRAPH-PATH", now,
                    "unverified", .5, [], raw.Select(e => e.EvidenceId));
                evidence = _store.GetEvidence(inc.IncidentId);
            }
        }

        // UNCALIBRATED heuristics. They order incidents for review; they are not probabilities.
        var rules = evidence.Select(Rule).Distinct().ToList();
        double severity = 1 - rules.Aggregate(1.0, (acc, r) => acc * (1 - RuleWeight.GetValueOrDefault(r, 0)));
        var perRoot = raw.SelectMany(e => e.ResolvedRoots.Select(r => (r, e.Confidence)))
            .GroupBy(t => t.r).Select(g => g.Max(t => t.Confidence));
        double confidence = Math.Min(.99, 1 - perRoot.Aggregate(1.0, (acc, c) => acc * (1 - c)));

        if (inc.TargetKind != "FileOccurrence")
        {
            var endpoint = raw.Where(e => Rule(e) == "R-LINEAGE-EGRESS")
                .GroupBy(e => e.SubjectKey)
                .OrderBy(g => _protected.IsProtectedEndpointKey(g.Key))
                .ThenByDescending(g => g.SelectMany(x => x.ResolvedRoots).Distinct().Count())
                .ThenByDescending(g => g.Max(x => x.ObservedMs)).FirstOrDefault();
            if (endpoint is not null) _store.SetIncidentTarget(inc.IncidentId, "NetworkEndpoint", endpoint.Key, null);
            else if (inc.TargetKind is null) _store.SetIncidentTarget(inc.IncidentId, "Process", inc.CorrelationKey, null);
        }

        var claims = new List<Claim>();
        foreach (var e in evidence.Where(e => e.ResolvedRoots.Count > 0))
        {
            // Naming the sensor is what lets a reader see why two similar facts count as independent.
            string detail = _detail.GetValueOrDefault(e.EvidenceId, "");
            if (detail.Length > 0 && e.TrustStatus == "verified") detail += $" (capture channel {e.CaptureChannel})";
            claims.Add(Rule(e) switch
            {
                "R-CANARY" => Explain.Fact("A decoy was touched. " + detail, [e.EvidenceId], e.ResolvedRoots, "D3FEND D3-DF Decoy File"),
                "R-INDICATOR" => Explain.Fact(detail.Length > 0 ? detail + "." : "A file hash matched a signed indicator.", [e.EvidenceId], e.ResolvedRoots, "Signed indicator bundle"),
                "R-PERSIST-UNTRUSTED" => Explain.Fact(detail + ".", [e.EvidenceId], e.ResolvedRoots, "ATT&CK TA0003 Persistence"),
                "R-LINEAGE-EGRESS" => Explain.Fact(detail + ".", [e.EvidenceId], e.ResolvedRoots, "ATT&CK TA0011 Command and Control (possible)"),
                "R-ML-ANOMALY" => Explain.Hypothesis("this lineage's 60-second activity ranked as unusual against the local baseline. This is a ranking signal only.", [e.EvidenceId], e.ResolvedRoots),
                "R-GRAPH-PATH" => Explain.Hypothesis("the observations above form a time-ordered chain. The chain restates those observations and adds no independent support.", [e.EvidenceId], e.ResolvedRoots),
                _ => Explain.Fact("Finding recorded.", [e.EvidenceId], e.ResolvedRoots)
            });
        }
        _store.AddHypothesis(HannibalStore.StableId("hyp", inc.IncidentId), inc.IncidentId, now, "evidence-bound-explanation",
            JsonSerializer.Serialize(claims), claims.SelectMany(c => c.RootEventIds).Distinct().Count());
        _store.UpdateIncident(inc.IncidentId, inc.Status == "contained" ? "contained" : "investigating", severity, confidence,
            JsonSerializer.Serialize(new { rules, heuristic = "uncalibrated" }), now);
        return evidence;
    }

    private PolicyDecision OverwatchDecide(IncidentRow inc, IReadOnlyList<EvidenceRow> evidence, long now,
        out string decisionId, out bool isNew)
    {
        string kindName = inc.TargetKind ?? "Process";
        var kind = Enum.Parse<TargetKind>(kindName);
        string key = inc.TargetKey ?? inc.CorrelationKey;
        bool isProtected = kind switch
        {
            TargetKind.NetworkEndpoint => _protected.IsProtectedEndpointKey(key),
            TargetKind.FileOccurrence => _protected.IsProtectedPath(_targetPath.GetValueOrDefault(key)),
            _ => true // automatic process termination is disabled by default: a process is never a containment target
        };
        bool local = StringComparer.Ordinal.Equals(inc.DeviceId, _opt.DeviceId);
        var target = new TargetIdentity(kind, inc.DeviceId, key, local, local, isProtected, inc.TargetSha256);

        var facts = evidence.Select(e => new VerifiedEvidenceFact(e.EvidenceId, Enum.Parse<EvidenceFamily>(e.Family),
            e.DeviceId, e.SubjectKey, e.CaptureChannel, e.ResolvedRoots, e.ObservedMs, e.Confidence,
            TrustedIngestVerified: e.TrustStatus == "verified")).ToList();

        var matches = new List<VerifiedMaliciousHashMatch>();
        if (kind == TargetKind.FileOccurrence && inc.TargetSha256 is not null)
            foreach (var r in _store.IndicatorsBySha(inc.TargetSha256))
                matches.Add(new VerifiedMaliciousHashMatch((string)r[0]!, (string)r[1]!, inc.TargetSha256, key, inc.DeviceId,
                    (string)r[2]!, SignatureVerified: (string)r[4]! != "unverified", IsRevoked: (string)r[4]! == "revoked",
                    ValidUntilMs: (long)r[3]!));

        var ctx = new SafetyContext(now, _ingestor.EssentialTelemetryHealthy(now),
            CalibrationVerified: _intake.PolicyVerified && _intake.Policy!.CalibrationAttested,
            SignedPolicyVerified: _intake.PolicyVerified);
        var decision = _policy.Evaluate(
            new VerifiedIncident(Guid.Parse(inc.IncidentId), inc.DeviceId, inc.Severity, inc.Confidence, target, facts, matches), ctx);

        isNew = !_lastDecision.TryGetValue(inc.IncidentId, out var last) || last.Kind != decision.Kind || last.Reason != decision.ReasonCode;
        decisionId = isNew ? Guid.NewGuid().ToString() : last.DecisionId;
        if (isNew)
        {
            string terminal = decision.Kind switch
            {
                DecisionKind.Observe => "MONITOR",
                DecisionKind.Quarantine or DecisionKind.TemporaryNetworkBlock => "SIMULATED_ACTION",
                _ => "ALERT"
            };
            var states = new[] { "OBSERVE", "TRIAGE", "VERIFY_EVIDENCE", "EVALUATE_POLICY", terminal };
            var body = JsonSerializer.Serialize(new
            {
                states, mode = _opt.Mode.ToString(), sentence = Explain.DecisionSentence(decision.ReasonCode),
                root_evidence_ids = evidence.SelectMany(e => e.ResolvedRoots).Distinct().ToArray(),
                unavailable_telemetry = TrustedIngestor.EssentialChannels.Where(c => _ingestor.ChannelStatus(c, now) != "healthy").ToArray(),
                policy_sha256 = _intake.PolicySha256, ttl_seconds = decision.TtlSeconds
            });
            _store.AddDecision(decisionId, inc.IncidentId, now, decision.Kind.ToString(), decision.Kind switch
            {
                DecisionKind.Quarantine or DecisionKind.TemporaryNetworkBlock => "allow",
                DecisionKind.Deny => "deny", DecisionKind.Alert => "alert", _ => "observe"
            }, decision.ReasonCode, body, evidence.Select(e => e.EvidenceId));
            _store.Audit.Append(now, "DECISION", JsonSerializer.Serialize(new
                { decisionId, inc.IncidentId, kind = decision.Kind.ToString(), decision.ReasonCode, states }));
            _lastDecision[inc.IncidentId] = (decision.Kind, decision.ReasonCode, decisionId);
        }
        return decision;
    }

    /// <summary>CounterOffensive agent, constrained to local, reversible, simulated countermeasures.</summary>
    private void LocalCountermeasures(IncidentRow inc, PolicyDecision decision, string decisionId, long now)
    {
        var cur = _store.GetLadder(inc.DeviceId, inc.CorrelationKey);
        var move = IsolationLadder.Next(
            cur is null ? null : new LadderState((IsolationRung)cur.Value.Rung, cur.Value.EnteredMs, cur.Value.ExpiresMs),
            decision.Kind, now);
        _store.SetLadder(inc.DeviceId, inc.CorrelationKey, (int)move.State.Rung, move.State.EnteredMs, move.State.ExpiresMs, decisionId);
        if (move.Changed)
            _store.Audit.Append(now, "LADDER", JsonSerializer.Serialize(new
                { inc.IncidentId, rung = move.State.Rung.ToString(), move.Reason, expires_ms = move.State.ExpiresMs }));

        bool wantBlock = decision.Kind == DecisionKind.TemporaryNetworkBlock && move.State.Rung >= IsolationRung.EnvelopEgress;
        bool wantHold = decision.Kind == DecisionKind.Quarantine && move.State.Rung == IsolationRung.Hold;
        if (!wantBlock && !wantHold) return;

        string idem = HannibalStore.StableId("idem", inc.IncidentId, decision.Kind.ToString(), decision.Target.IdentityKey);
        var args = new Dictionary<string, string>
        {
            ["decision_id"] = decisionId, ["idempotency_key"] = idem, ["device_id"] = inc.DeviceId,
            ["target_key"] = decision.Target.IdentityKey, ["policy_sha256"] = _intake.PolicySha256 ?? ""
        };
        BrokerResponse resp;
        if (wantBlock)
        {
            args["ttl_seconds"] = Math.Min(decision.TtlSeconds ?? 900, 900).ToString();
            resp = _broker.Send(BrokerCommand.SimulateNetworkBlock, args);
        }
        else
        {
            args["sha256"] = decision.Target.FileSha256 ?? "";
            args["path"] = _targetPath.GetValueOrDefault(decision.Target.IdentityKey, "");
            resp = _broker.Send(BrokerCommand.SimulateQuarantine, args);
        }
        if (resp.Code == "IDEMPOTENT_REPLAY") return; // already recorded on an earlier evaluation

        string state = resp.Ok ? "executed" : "failed";
        _store.RecordContainment(resp.ActionId ?? Guid.NewGuid().ToString(), idem, decisionId, inc.DeviceId,
            wantBlock ? "temporary_network_block" : "quarantine", decision.Target.Kind.ToString(),
            decision.Target.IdentityKey, state, now, resp.ExpiresMs, resp.RollbackToken, JsonSerializer.Serialize(resp));
        _store.Audit.Append(now, "VERIFY_EFFECT", JsonSerializer.Serialize(new
            { decisionId, broker_code = resp.Code, resp.ActionId, simulated = true, next = resp.Ok ? "REASSESS" : "ALERT" }));
        if (resp.Ok) _store.UpdateIncident(inc.IncidentId, "contained", inc.Severity, inc.Confidence, inc.ReasonJson, now);
    }

    /// <summary>RECOVER: undo a simulated action by its restore token. Idempotent.</summary>
    public BrokerResponse Restore(string rollbackToken)
    {
        var resp = _broker.Send(BrokerCommand.Rollback, new() { ["rollback_token"] = rollbackToken });
        _store.Audit.Append(_clock(), "RECOVER", JsonSerializer.Serialize(new { resp.Code, resp.ActionId }));
        if (resp.Ok && resp.ActionId is not null)
        {
            // A restore is an operator's decision: the incident is closed and is not re-evaluated.
            _store.Db.Execute(Sql.RollbackContainment, _clock(), resp.ActionId);
            _store.Db.Execute(Sql.ResolveByAction, _clock(), resp.ActionId);
        }
        return resp;
    }

    public void RegisterCanaries(IEnumerable<CanarySpec> specs, string status = "planned")
    {
        long now = _clock();
        foreach (var s in specs)
            _store.UpsertCanary(new CanaryRow(s.CanaryId, _opt.DeviceId, s.DecoyKind, s.Location, null, null, s.SizeBytes, status), now);
    }

    public CoreOptions Options => _opt;
    public HannibalStore Store => _store;
    public TrustedIngestor Ingestor => _ingestor;
    public BundleIntake Intake => _intake;
    public BrokerClient Broker => _broker;
}
