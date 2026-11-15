using Hannibal.Contracts;

namespace Hannibal.Overwatch;

// These are VERIFIED inputs from a trusted ingestor. Individual AI agents are
// untrusted producers and must not set TrustedIngestVerified themselves.
public sealed record VerifiedEvidenceFact(
    string EvidenceId,
    EvidenceFamily Family,
    string DeviceId,
    string SubjectKey,
    string CaptureChannel,
    IReadOnlyList<string> RawRootEventIds,
    long ObservedMs,
    double Confidence,
    bool TrustedIngestVerified);

public sealed record VerifiedMaliciousHashMatch(
    string IndicatorId,
    string IndicatorSha256,
    string ObservedFileSha256,
    string FileIdentityKey,
    string DeviceId,
    string SignedBundleId,
    bool SignatureVerified,
    bool IsRevoked,
    long ValidUntilMs);

public sealed record VerifiedIncident(
    Guid IncidentId,
    string DeviceId,
    double Severity,
    double Confidence,
    TargetIdentity Target,
    IReadOnlyList<VerifiedEvidenceFact> Evidence,
    IReadOnlyList<VerifiedMaliciousHashMatch> MaliciousFileMatches);

public sealed record SafetyContext(
    long NowMs,
    bool EssentialTelemetryHealthy,
    bool CalibrationVerified,
    bool SignedPolicyVerified,
    long EvidenceMaxAgeMs = 120_000L);

public interface ISafeOverwatchPolicyEngine
{
    PolicyDecision Evaluate(VerifiedIncident incident, SafetyContext context);
}
