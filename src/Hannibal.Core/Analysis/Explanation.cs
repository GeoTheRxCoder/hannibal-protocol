using System.Text;

namespace Hannibal.Core.Analysis;

public sealed record Claim(string Text, bool IsHypothesis, IReadOnlyList<string> EvidenceIds,
    IReadOnlyList<string> RootEventIds, IReadOnlyList<string> References);

/// <summary>
/// Evidence-bound explanations. Each sentence is a template filled from
/// structured findings and carries the evidence and raw-root IDs it rests on.
/// A claim with no root is refused. Strings that originate on the endpoint
/// (file names, command lines) are attacker-controlled: they are sanitized,
/// length-capped and quoted as data. This is the contract a future local
/// language model must satisfy too - rephrase the claim list, add nothing,
/// and hold no action authority.
/// </summary>
public static class Explain
{
    public static string Untrusted(string? value, int max = 96)
    {
        if (string.IsNullOrEmpty(value)) return "«»";
        var sb = new StringBuilder();
        foreach (var ch in value)
        {
            if (sb.Length >= max) { sb.Append('…'); break; }
            bool bidi = ch is >= '‪' and <= '‮' or >= '⁦' and <= '⁩' or '‎' or '‏';
            sb.Append(char.IsControl(ch) || bidi || ch is '«' or '»' || char.IsSurrogate(ch) ? '?' : ch);
        }
        return "«" + sb + "»";
    }

    public static Claim Fact(string text, IEnumerable<string> evidenceIds, IEnumerable<string> roots, params string[] refs) =>
        Make(text, false, evidenceIds, roots, refs);

    public static Claim Hypothesis(string text, IEnumerable<string> evidenceIds, IEnumerable<string> roots, params string[] refs) =>
        Make("Hypothesis: " + text, true, evidenceIds, roots, refs);

    private static Claim Make(string text, bool hyp, IEnumerable<string> ev, IEnumerable<string> roots, string[] refs)
    {
        var r = roots.Distinct(StringComparer.Ordinal).ToList();
        if (r.Count == 0) throw new InvalidOperationException("A claim without a raw evidence root is not allowed");
        return new Claim(text, hyp, ev.Distinct(StringComparer.Ordinal).ToList(), r, refs);
    }

    /// <summary>Brand-voice summary line for a decision. States scope and next step; no absolute claims.</summary>
    public static string DecisionSentence(string reasonCode) => reasonCode switch
    {
        "TWO_DISTINCT_RAW_OBSERVATIONS" => "Two independent raw observations support policy review on this authorized device.",
        "MATCHED_SIGNED_MALICIOUS_ARTIFACT" => "This file matches an entry in a signed, unrevoked indicator bundle on this authorized device.",
        "PROTECTED_TARGET" => "No automatic action applies to this target: it is protected, or it is a process, which is never terminated automatically. Review is advised.",
        "OUTSIDE_AUTHORIZED_SCOPE" => "The target is outside this device's authorized scope. The request was denied.",
        "DEGRADED_TRUST_OR_TELEMETRY" => "Telemetry or policy trust is degraded. New actions are declined until health is restored.",
        "INVALID_INCIDENT_SCORE" => "The incident score was not a valid number. New actions are declined.",
        "REQUIRES_INVESTIGATION" => "The evidence supports investigation. It does not meet the bar for containment.",
        _ => "No corroborated threat. Observation continues."
    };
}
