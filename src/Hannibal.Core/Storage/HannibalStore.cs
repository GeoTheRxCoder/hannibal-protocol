using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Hannibal.Core.Storage;

public sealed record JournalEntry(
    long Seq, string EventId, string DeviceId, string Kind, long ObservedMs, string SubjectKey,
    IReadOnlyDictionary<string, string> Fields, string RootEventId, string CaptureChannel, string CollectorId)
{
    public string Field(string name) => Fields.TryGetValue(name, out var v) ? v : "";
}

public sealed record EvidenceRow(
    string EvidenceId, string IncidentId, string DeviceId, string SubjectKey, string Family,
    string CaptureChannel, string ProducerId, long ObservedMs, string TrustStatus, double Confidence,
    IReadOnlyList<string> ResolvedRoots);

public sealed record IncidentRow(
    string IncidentId, string DeviceId, string CorrelationKey, string Status, double Severity,
    double Confidence, long OpenedMs, long UpdatedMs, string ReasonJson,
    string? TargetKind, string? TargetKey, string? TargetSha256);

public sealed record CanaryRow(
    string CanaryId, string DeviceId, string DecoyKind, string Location, string? FileIdentityKey,
    string? Sha256, long SizeBytes, string Status);

public sealed record EdgeObservationRow(
    string Src, string SrcType, string Dst, string DstType, string Relation, string DeviceId,
    long ObservedMs, double Confidence, long EventSeq, string RootEventId);

/// <summary>
/// The durable journal and repository for the Core service. Single writer;
/// every consumer applies its mutations and advances its offset inside one
/// transaction (see <see cref="Transact"/>), so a crash replays cleanly.
/// </summary>
public sealed class HannibalStore : IDisposable
{
    public SqliteDb Db { get; }
    public AuditChain Audit { get; }

    private HannibalStore(SqliteDb db) { Db = db; Audit = new AuditChain(db); }

    public static HannibalStore Open(string path)
    {
        var db = SqliteDb.Open(path);
        db.Exec("PRAGMA synchronous=FULL;");
        foreach (var name in new[] { "001_initial.sql", "002_evidence_provenance.sql", "003_beta_runtime.sql" })
            db.Exec(ReadSchema(name));
        return new HannibalStore(db);
    }

    public static string ReadSchema(string name)
    {
        var asm = typeof(HannibalStore).Assembly;
        var res = asm.GetManifestResourceNames().Single(n => n.EndsWith(name, StringComparison.Ordinal));
        using var r = new StreamReader(asm.GetManifestResourceStream(res)!);
        return r.ReadToEnd();
    }

    public void Transact(Action body) => Db.Transact(body);
    public void Dispose() => Db.Dispose();

    public static string StableId(string prefix, params string[] parts) =>
        prefix + "-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\u001f", parts))))[..32];

    // ---- Journal -----------------------------------------------------------

    /// <summary>Idempotent on event_id: a duplicate returns the existing sequence number.</summary>
    public long AppendObservation(string eventId, string deviceId, string kind, long observedMs, long ingestedMs,
        string subjectKey, string fieldsJson, string rootEventId, string captureChannel, string collectorId)
    {
        long seq = 0;
        Db.Transact(() =>
        {
            var existing = Db.Scalar(Sql.EventSeqById, eventId);
            if (existing is long s) { seq = s; return; }
            Db.Execute(Sql.InsertEvent, eventId, deviceId, kind, observedMs, ingestedMs, rootEventId, subjectKey, fieldsJson);
            seq = Db.LastInsertRowId;
            Db.Execute(Sql.InsertEventRoot, seq, rootEventId, captureChannel, collectorId);
        });
        return seq;
    }

    public IReadOnlyList<JournalEntry> ReadAfter(long lastSeq, int max)
    {
        var list = new List<JournalEntry>();
        foreach (var r in Db.Query(Sql.ReadEventsAfter, lastSeq, max))
            list.Add(new JournalEntry((long)r[0]!, (string)r[1]!, (string)r[2]!, (string)r[3]!, (long)r[4]!,
                (string?)r[5] ?? "", ParseFields((string)r[6]!), (string)r[7]!, (string)r[8]!, (string)r[9]!));
        return list;
    }

    private static Dictionary<string, string> ParseFields(string json) =>
        JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new();

    public long GetOffset(string consumer) => Db.Scalar(Sql.GetOffset, consumer) as long? ?? 0;

    public void SetOffset(string consumer, long seq, long nowMs) => Db.Execute(Sql.UpsertOffset, consumer, seq, nowMs);

    public bool RootSeenOnOtherChannel(string rootEventId, string channel) =>
        Db.Scalar(Sql.RootOnOtherChannel, rootEventId, channel) is not null;

    // ---- Graph -------------------------------------------------------------

    public string UpsertNode(string deviceId, string type, string identityKey, long ms)
    {
        var id = StableId("n", deviceId, type, identityKey);
        Db.Execute(Sql.UpsertNode, id, deviceId, type, identityKey, ms, ms);
        return id;
    }

    public string UpsertEdgeObservation(string srcNode, string dstNode, string relation, long ms,
        double confidence, long eventSeq, string rootEventId, string deviceId)
    {
        var id = StableId("e", srcNode, dstNode, relation);
        Db.Execute(Sql.UpsertEdge, id, srcNode, dstNode, relation, ms, ms, confidence);
        Db.Execute(Sql.InsertRawEdgeObs, id, eventSeq, rootEventId, ms, deviceId);
        return id;
    }

    public IReadOnlyList<EdgeObservationRow> LoadEdgeObservations(string deviceId, long startMs, long endMs, int limit = 5000)
    {
        var list = new List<EdgeObservationRow>();
        foreach (var r in Db.Query(Sql.LoadEdgeObs, deviceId, startMs, endMs, limit))
            list.Add(new EdgeObservationRow((string)r[0]!, (string)r[1]!, (string)r[2]!, (string)r[3]!, (string)r[4]!,
                (string)r[5]!, (long)r[6]!, Convert.ToDouble(r[7]), (long)r[8]!, (string)r[9]!));
        return list;
    }

    public long Count(string table) => table switch
    {
        "graph_nodes" or "graph_edges" or "security_events" or "incidents" or "evidence_records"
            or "policy_decisions" or "containment_actions" or "canary_manifest" =>
            (long)Db.Scalar("SELECT COUNT(*) FROM " + table)!,
        _ => throw new ArgumentException("Unknown table")
    };

    // ---- Incidents and evidence -------------------------------------------

    public string OpenIncident(string deviceId, string correlationKey, long nowMs)
    {
        if (Db.Scalar(Sql.IncidentByKey, deviceId, correlationKey) is string existing) return existing;
        var id = Guid.NewGuid().ToString();
        Db.Transact(() =>
        {
            Db.Execute(Sql.InsertIncident, id, deviceId, nowMs, nowMs);
            Db.Execute(Sql.InsertIncidentKey, deviceId, correlationKey, id);
        });
        return id;
    }

    public void UpdateIncident(string incidentId, string status, double severity, double confidence,
        string reasonJson, long nowMs) =>
        Db.Execute(Sql.UpdateIncident, status, severity, confidence, nowMs, reasonJson, incidentId);

    public void SetIncidentTarget(string incidentId, string kind, string key, string? sha256) =>
        Db.Execute(Sql.SetIncidentTarget, kind, key, sha256, incidentId);

    public IncidentRow? GetIncident(string incidentId) =>
        Incidents(Sql.SelectIncidents + " WHERE i.incident_id=?", incidentId).FirstOrDefault();

    public IReadOnlyList<IncidentRow> ListIncidents(int limit = 50) =>
        Incidents(Sql.SelectIncidents + " ORDER BY i.updated_ms DESC LIMIT ?", limit);

    private List<IncidentRow> Incidents(string sql, params object?[] args)
    {
        var list = new List<IncidentRow>();
        foreach (var r in Db.Query(sql, args))
            list.Add(new IncidentRow((string)r[0]!, (string)r[1]!, (string)r[2]!, (string)r[3]!, Convert.ToDouble(r[4]),
                Convert.ToDouble(r[5]), (long)r[6]!, (long)r[7]!, (string)r[8]!, (string?)r[9], (string?)r[10], (string?)r[11]));
        return list;
    }

    /// <summary>
    /// Adds a finding. Raw findings carry roots directly; derived findings
    /// (graph, ML) name their parents and inherit the parents' roots. A parent
    /// link that would create a cycle is rejected.
    /// </summary>
    public bool AddEvidence(string evidenceId, string incidentId, long? sourceEventSeq, string deviceId,
        string subjectKey, string family, string captureChannel, string producerId, long observedMs,
        string trustStatus, double confidence, IEnumerable<string> roots, IEnumerable<string>? parents = null)
    {
        bool added = false;
        Db.Transact(() =>
        {
            added = Db.Execute(Sql.InsertEvidence, evidenceId, incidentId, sourceEventSeq, deviceId, subjectKey,
                family, captureChannel, producerId, observedMs, trustStatus, confidence) > 0;
            if (!added) return;
            foreach (var root in roots.Distinct(StringComparer.Ordinal))
                Db.Execute(Sql.InsertEvidenceRoot, evidenceId, root);
            foreach (var p in parents ?? [])
            {
                if (p == evidenceId || Ancestors(p).Contains(evidenceId))
                    throw new InvalidOperationException("Evidence derivation cycle rejected");
                Db.Execute(Sql.InsertDerivation, evidenceId, p);
            }
        });
        return added;
    }

    private HashSet<string> Ancestors(string evidenceId)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var stack = new Stack<string>([evidenceId]);
        while (stack.Count > 0)
            foreach (var r in Db.Query(Sql.ParentsOf, stack.Pop()))
                if (seen.Add((string)r[0]!)) stack.Push((string)r[0]!);
        return seen;
    }

    /// <summary>Roots resolved recursively through the derivation graph.</summary>
    public IReadOnlyList<string> ResolveRoots(string evidenceId)
    {
        var roots = new SortedSet<string>(StringComparer.Ordinal);
        var all = Ancestors(evidenceId); all.Add(evidenceId);
        foreach (var id in all)
            foreach (var r in Db.Query(Sql.RootsOf, id)) roots.Add((string)r[0]!);
        return roots.ToList();
    }

    public IReadOnlyList<EvidenceRow> GetEvidence(string incidentId)
    {
        var list = new List<EvidenceRow>();
        foreach (var r in Db.Query(Sql.EvidenceByIncident, incidentId))
            list.Add(new EvidenceRow((string)r[0]!, (string)r[1]!, (string)r[2]!, (string)r[3]!, (string)r[4]!,
                (string)r[5]!, (string)r[6]!, (long)r[7]!, (string)r[8]!, Convert.ToDouble(r[9]),
                ResolveRoots((string)r[0]!)));
        return list;
    }

    public void AddHypothesis(string id, string incidentId, long nowMs, string kind, string explanationJson, int rootCount) =>
        Db.Execute(Sql.InsertHypothesis, id, incidentId, nowMs, kind, explanationJson, rootCount);

    public string? LatestHypothesis(string incidentId) => (string?)Db.Scalar(Sql.LatestHypothesis, incidentId);

    // ---- Decisions and actions --------------------------------------------

    public void AddDecision(string decisionId, string incidentId, long nowMs, string actionType, string outcome,
        string reasonCode, string evidenceJson, IEnumerable<string> evidenceIds)
    {
        Db.Transact(() =>
        {
            Db.Execute(Sql.InsertDecision, decisionId, incidentId, nowMs, actionType, outcome, reasonCode, evidenceJson);
            foreach (var e in evidenceIds) Db.Execute(Sql.InsertDecisionEvidence, decisionId, e);
        });
    }

    public (string ReasonCode, string ActionType, long DecisionMs)? LatestDecision(string incidentId)
    {
        var r = Db.Query(Sql.LatestDecision, incidentId).FirstOrDefault();
        return r is null ? null : ((string)r[0]!, (string)r[1]!, (long)r[2]!);
    }

    public void RecordContainment(string actionId, string idempotencyKey, string decisionId, string deviceId,
        string actionType, string targetType, string targetKey, string state, long nowMs, long? expiresMs,
        string? rollbackToken, string receiptJson) =>
        Db.Execute(Sql.UpsertContainment, actionId, idempotencyKey, decisionId, deviceId, actionType, targetType,
            targetKey, state, nowMs, nowMs, expiresMs, rollbackToken, receiptJson);

    public IReadOnlyList<object?[]> ListContainment(string decisionIncidentId) =>
        Db.Query(Sql.ContainmentByIncident, decisionIncidentId);

    // ---- Deception, ladder, coverage, bundles, health ----------------------

    public void UpsertCanary(CanaryRow c, long nowMs) =>
        Db.Execute(Sql.UpsertCanary, c.CanaryId, c.DeviceId, c.DecoyKind, c.Location, c.FileIdentityKey,
            c.Sha256, c.SizeBytes, c.Status, nowMs);

    public IReadOnlyList<CanaryRow> ListCanaries(string deviceId)
    {
        var list = new List<CanaryRow>();
        foreach (var r in Db.Query(Sql.ListCanaries, deviceId))
            list.Add(new CanaryRow((string)r[0]!, (string)r[1]!, (string)r[2]!, (string)r[3]!, (string?)r[4],
                (string?)r[5], (long)r[6]!, (string)r[7]!));
        return list;
    }

    public void MarkCanary(string canaryId, string status, long nowMs) => Db.Execute(Sql.MarkCanary, status, nowMs, canaryId);

    public (int Rung, long EnteredMs, long ExpiresMs)? GetLadder(string deviceId, string subjectKey)
    {
        var r = Db.Query(Sql.GetLadder, deviceId, subjectKey).FirstOrDefault();
        return r is null ? null : ((int)(long)r[0]!, (long)r[1]!, (long)r[2]!);
    }

    public void SetLadder(string deviceId, string subjectKey, int rung, long enteredMs, long expiresMs, string? decisionId) =>
        Db.Execute(Sql.UpsertLadder, deviceId, subjectKey, rung, enteredMs, expiresMs, decisionId);

    public IReadOnlyList<object?[]> ListLadder(string deviceId) => Db.Query(Sql.ListLadder, deviceId);

    public void SetAxis(string deviceId, string axis, string channel, string status, long nowMs) =>
        Db.Execute(Sql.UpsertAxis, deviceId, axis, channel, status, nowMs);

    public IReadOnlyList<object?[]> ListAxes(string deviceId) => Db.Query(Sql.ListAxes, deviceId);

    public long LastBundleVersion(string bundleType) => Db.Scalar(Sql.BundleVersion, bundleType) as long? ?? 0;

    public void AcceptBundle(string type, string id, long version, string sha256, long nowMs, long expiresMs) =>
        Db.Execute(Sql.UpsertBundle, type, id, version, sha256, nowMs, expiresMs);

    public IReadOnlyList<object?[]> ListBundles() => Db.Query(Sql.ListBundles);

    public void UpsertIndicator(string indicatorId, string sha256, string bundleId, string sigRef, long verifiedMs,
        long validUntilMs, string status) =>
        Db.Execute(Sql.UpsertIndicator, indicatorId, sha256, bundleId, sigRef, verifiedMs, validUntilMs, status);

    public IReadOnlyList<object?[]> IndicatorsBySha(string sha256) => Db.Query(Sql.IndicatorsBySha, sha256.ToLowerInvariant());

    public void SetCollectorHealth(string collectorId, string channel, long lastSeq, long nowMs, long lost,
        long rejected, string status) =>
        Db.Execute(Sql.UpsertCollector, collectorId, channel, lastSeq, nowMs, lost, rejected, status);

    public IReadOnlyList<object?[]> ListCollectors() => Db.Query(Sql.ListCollectors);

    public void Heartbeat(string agent, long nowMs, long lastSeq, string health, string detailsJson) =>
        Db.Execute(Sql.UpsertHeartbeat, agent, nowMs, lastSeq, health, detailsJson);

    public IReadOnlyList<object?[]> ListHeartbeats() => Db.Query(Sql.ListHeartbeats);

    /// <summary>Records first sight of an executable hash; returns the first-seen time.</summary>
    public long TouchHash(string deviceId, string sha256, long nowMs)
    {
        Db.Execute(Sql.InsertHashFirstSeen, deviceId, sha256.ToLowerInvariant(), nowMs);
        return (long)Db.Scalar(Sql.HashFirstSeen, deviceId, sha256.ToLowerInvariant())!;
    }

    public long BaselineStartedMs(string deviceId, long nowMs)
    {
        Db.Execute(Sql.InsertBaseline, deviceId, nowMs);
        return (long)Db.Scalar(Sql.GetBaseline, deviceId)!;
    }

    public void SaveFeatureWindow(string id, string deviceId, string processKey, long startMs, long endMs,
        string schema, string featureJson, double coverage, double? anomalyRatio) =>
        Db.Execute(Sql.InsertFeatureWindow, id, deviceId, processKey, startMs, endMs, schema, featureJson, coverage, anomalyRatio);
}
