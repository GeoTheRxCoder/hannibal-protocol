using Hannibal.Contracts;

namespace Hannibal.Overwatch;

/// <summary>
/// Reference-only, conservative policy. Trust validation occurs upstream,
/// then MUST be repeated by the privileged Containment Broker.
/// No endpoint actions are implemented by this file.
/// </summary>
public sealed class SafeOverwatchPolicyEngine : ISafeOverwatchPolicyEngine
{
    public PolicyDecision Evaluate(VerifiedIncident incident, SafetyContext ctx)
    {
        var t = incident.Target;
        PolicyDecision Decide(DecisionKind kind, string reason, int? ttl = null)
            => new(kind, reason, incident.IncidentId, t, ttl);

        if (!t.IsLocal || !t.IsAuthorized ||
            !StringComparer.Ordinal.Equals(t.DeviceId, incident.DeviceId))
            return Decide(DecisionKind.Deny, "OUTSIDE_AUTHORIZED_SCOPE");

        if (t.IsProtected)
            return Decide(DecisionKind.Alert, "PROTECTED_TARGET");

        if (!ctx.SignedPolicyVerified ||
            !ctx.EssentialTelemetryHealthy)
            return Decide(DecisionKind.Alert, "DEGRADED_TRUST_OR_TELEMETRY");

        if (!ValidProbability(incident.Severity) ||
            !ValidProbability(incident.Confidence))
            return Decide(DecisionKind.Alert, "INVALID_INCIDENT_SCORE");

        // Only a cryptographically validated indicator that MATCHES this file
        // occurrence can make it eligible. Broker must re-hash the same file
        // object handle and independently check the signed indicator bundle.
        if (t.Kind == TargetKind.FileOccurrence &&
            IsSha256(t.FileSha256 ?? "") &&
            (incident.MaliciousFileMatches ?? []).Any(m =>
                m.SignatureVerified && !m.IsRevoked &&
                !string.IsNullOrWhiteSpace(m.SignedBundleId) &&
                ctx.NowMs < m.ValidUntilMs &&
                StringComparer.Ordinal.Equals(m.DeviceId, incident.DeviceId) &&
                StringComparer.Ordinal.Equals(m.FileIdentityKey, t.IdentityKey) &&
                StringComparer.OrdinalIgnoreCase.Equals(m.IndicatorSha256, t.FileSha256) &&
                StringComparer.OrdinalIgnoreCase.Equals(m.ObservedFileSha256, t.FileSha256)))
            return Decide(DecisionKind.Quarantine, "MATCHED_SIGNED_MALICIOUS_ARTIFACT");

        // Restrictive network rule: confidence is only a guard. Corroboration
        // must come from two independent RAW observations with distinct capture
        // channels, not e.g. an ETW event and a graph finding derived from it.
        if (t.Kind == TargetKind.NetworkEndpoint &&
            ctx.CalibrationVerified &&
            incident.Severity >= .85 &&
            incident.Confidence >= .90)
        {
            var credible = (incident.Evidence ?? Array.Empty<VerifiedEvidenceFact>())
                .Where(e => e.TrustedIngestVerified &&
                            (e.Family == EvidenceFamily.Behavior ||
                             e.Family == EvidenceFamily.Reputation ||
                             e.Family == EvidenceFamily.Signature) &&
                            StringComparer.Ordinal.Equals(e.DeviceId, incident.DeviceId) &&
                            StringComparer.Ordinal.Equals(e.SubjectKey, t.IdentityKey) &&
                            e.ObservedMs <= ctx.NowMs &&
                            e.ObservedMs >= ctx.NowMs - ctx.EvidenceMaxAgeMs &&
                            ValidProbability(e.Confidence) && e.Confidence >= .80 &&
                            !string.IsNullOrWhiteSpace(e.CaptureChannel) &&
                            e.RawRootEventIds is { Count: > 0 } &&
                            e.RawRootEventIds.All(id => !string.IsNullOrWhiteSpace(id)))
                .ToArray();

            for (var i = 0; i < credible.Length; i++)
            for (var j = i + 1; j < credible.Length; j++)
                if (Independent(credible[i], credible[j]))
                    return Decide(DecisionKind.TemporaryNetworkBlock,
                        "TWO_DISTINCT_RAW_OBSERVATIONS", 900);
        }

        if (incident.Severity >= .45 || (incident.Evidence?.Count ?? 0) > 0 ||
            (incident.MaliciousFileMatches?.Count ?? 0) > 0)
            return Decide(DecisionKind.Alert, "REQUIRES_INVESTIGATION");

        return Decide(DecisionKind.Observe, "NO_CORROBORATED_THREAT");
    }

    private static bool Independent(VerifiedEvidenceFact a, VerifiedEvidenceFact b)
    {
        if (StringComparer.Ordinal.Equals(a.CaptureChannel, b.CaptureChannel))
            return false;
        var roots = new HashSet<string>(a.RawRootEventIds, StringComparer.Ordinal);
        return !b.RawRootEventIds.Any(roots.Contains);
    }

    private static bool IsSha256(string s) =>
        s.Length == 64 && s.All(c =>
            c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static bool ValidProbability(double n) =>
        double.IsFinite(n) && n >= 0 && n <= 1;
}
