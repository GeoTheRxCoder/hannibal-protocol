using System.Text.Json;

namespace Hannibal.Contracts;

public enum AgentId
{
    Sentry, Reconnaissance, ThreatDetection, TacticalML,
    ThreatAnalysis, CounterOffensive, Overwatch
}
public enum TargetKind { Process, FileOccurrence, NetworkEndpoint }
public enum EvidenceFamily { Signature, Reputation, Behavior, Graph, MlAnomaly, Exposure }
public enum ContainmentKind { Quarantine, TemporaryNetworkBlock, TerminateProcess }
public enum DecisionKind { Observe, Alert, Quarantine, TemporaryNetworkBlock, Deny }

public sealed record SecurityEvent(
    Guid EventId,
    int SchemaVersion,
    string DeviceId,
    AgentId SourceAgent,
    string EventType,
    long ObservedMs,
    string? CorrelationId,
    string? SubjectKey,
    string PrivacyClass,
    JsonElement Payload,
    long EventSeq = 0
);

public sealed record AgentHealth(
    AgentId Agent,
    long LastSeenMs,
    long LastEventSeq,
    string State
);

public sealed record GraphNode(
    string Id, string DeviceId, string Type, string IdentityKey,
    long FirstSeenMs, long LastSeenMs, JsonElement Properties
);
public sealed record GraphEdge(
    string Id, string SourceNodeId, string TargetNodeId,
    string RelationType, double Confidence,
    long FirstSeenMs, long LastSeenMs
);

public sealed record EvidenceSignal(
    EvidenceFamily Family,
    string IndependentSourceKey,
    double Confidence,
    bool ProvenanceValidated
);

public sealed record TargetIdentity(
    TargetKind Kind,
    string DeviceId,
    string IdentityKey,
    bool IsLocal,
    bool IsAuthorized,
    bool IsProtected,
    string? FileSha256 = null,
    int? ProcessId = null,
    long? ProcessStartMs = null
);

public sealed record IncidentSnapshot(
    Guid IncidentId,
    string DeviceId,
    double Severity,
    double Confidence,
    TargetIdentity Target,
    IReadOnlyList<EvidenceSignal> Evidence
);

public sealed record PolicyDecision(
    DecisionKind Kind,
    string ReasonCode,
    Guid IncidentId,
    TargetIdentity Target,
    int? TtlSeconds = null
);

public sealed record ApprovedActionRequest(
    Guid DecisionId,
    string PolicyId,
    int PolicyVersion,
    string IdempotencyKey,
    ContainmentKind Kind,
    TargetIdentity Target,
    string SignedAuthorizationRef,
    int? TtlSeconds
);

public sealed record ContainmentReceipt(
    Guid ActionId,
    bool Executed,
    string ResultCode,
    string? RollbackToken
);

public sealed record ModelScore(
    string ModelId,
    int ClusterIndex,
    double Distance,
    double CalibratedThreshold,
    double AnomalyRatio,
    double FeatureCoverage,
    bool IsScorable,
    int ExceededTrainingCaps = 0
);

public interface ISecurityAgent
{
    AgentId Id { get; }
    ValueTask ProcessAsync(SecurityEvent evt, CancellationToken ct);
    AgentHealth GetHealth();
}

public interface IEventJournal
{
    ValueTask<long> AppendAsync(SecurityEvent evt, CancellationToken ct);
    IAsyncEnumerable<SecurityEvent> ReadAfterAsync(
        string consumerName, long lastSeq, int batchSize, CancellationToken ct);
    ValueTask CommitOffsetAsync(string consumerName, long lastSeq, CancellationToken ct);
}

public interface IThreatGraph
{
    ValueTask UpsertNodeAsync(GraphNode node, CancellationToken ct);
    ValueTask UpsertEdgeAsync(GraphEdge edge, long evidenceEventSeq, CancellationToken ct);
    ValueTask<IReadOnlyList<GraphEdge>> GetNeighborsAsync(
        string nodeId, int maxDepth, int maxEdges, CancellationToken ct);
}

public interface IFeatureExtractor
{
    ValueTask<(double[] Features, double Coverage)> ExtractAsync(
        string processIdentityKey, long windowEndMs, CancellationToken ct);
}

public interface IAnomalyScorer
{
    ModelScore Score(ReadOnlySpan<double> rawFeatures, double coverage);
}

public interface IOverwatchPolicyEngine
{
    PolicyDecision Evaluate(IncidentSnapshot incident);
}

public interface IContainmentBroker
{
    // A broker must revalidate caller, signatures, scope, target identity,
    // Windows protection state, expiry and idempotency, not trust request fields.
    ValueTask<ContainmentReceipt> ExecuteAsync(
        ApprovedActionRequest request, CancellationToken ct);
    ValueTask<ContainmentReceipt> RollbackAsync(
        string rollbackToken, CancellationToken ct);
}

public interface IOverwatchCoordinator
{
    ValueTask HandleIncidentAsync(Guid incidentId, CancellationToken ct);
}
