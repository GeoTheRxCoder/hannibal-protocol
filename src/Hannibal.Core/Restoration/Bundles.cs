using System.Text.Json;
using Hannibal.Core.Crypto;
using Hannibal.Core.Identity;
using Hannibal.Core.Storage;

namespace Hannibal.Core.Restoration;

public sealed record Indicator(string IndicatorId, string Sha256, long ValidUntilMs);

/// <summary>Payload of a signed "indicators" bundle.</summary>
public sealed record IndicatorBundle(IReadOnlyList<Indicator> Indicators, IReadOnlySet<string> Revoked)
{
    public static IndicatorBundle? Parse(VerifiedBundle b)
    {
        try
        {
            var list = new List<Indicator>();
            foreach (var i in b.Payload.GetProperty("indicators").EnumerateArray())
            {
                var sha = i.GetProperty("sha256").GetString()!;
                if (!IdentityKeys.IsSha256(sha)) return null;
                long until = i.TryGetProperty("valid_until_ms", out var v) ? v.GetInt64() : b.ExpiresMs;
                list.Add(new Indicator(i.GetProperty("indicator_id").GetString()!, sha.ToLowerInvariant(), until));
            }
            var revoked = new HashSet<string>(StringComparer.Ordinal);
            if (b.Payload.TryGetProperty("revoked", out var rv))
                foreach (var r in rv.EnumerateArray()) revoked.Add(r.GetString()!);
            return new IndicatorBundle(list, revoked);
        }
        catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException or FormatException) { return null; }
    }
}

/// <summary>Payload of a signed "policy" bundle. Thresholds live in the reviewed policy engine, not here.</summary>
public sealed record PolicyBundle(string Mode, bool CalibrationAttested, string? CalibrationReportSha256)
{
    public static PolicyBundle? Parse(VerifiedBundle b)
    {
        try
        {
            var p = b.Payload;
            var mode = p.GetProperty("mode").GetString()!;
            bool cal = p.TryGetProperty("calibration_attested", out var c) && c.GetBoolean();
            string? rep = p.TryGetProperty("calibration_report_sha256", out var r) ? r.GetString() : null;
            // A calibration attestation must name the evaluation report it refers to.
            if (cal && !IdentityKeys.IsSha256(rep)) return null;
            return mode is "simulation" or "enforcing" ? new PolicyBundle(mode, cal, rep) : null;
        }
        catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException) { return null; }
    }
}

/// <summary>
/// "Logistics and restoration" (Hatshepsut motif): the supply line that
/// brings signed material in, and the record that lets any action be undone.
/// Intake is all-or-nothing and monotonic.
/// </summary>
public sealed class BundleIntake(HannibalStore store, TrustRoot trust, Func<long> clock)
{
    public PolicyBundle? Policy { get; private set; }
    public string? PolicySha256 { get; private set; }
    public long PolicyExpiresMs { get; private set; }

    public bool PolicyVerified => Policy is not null && clock() < PolicyExpiresMs;

    public BundleFailure AcceptPolicy(byte[] bundle, string signatureJson)
    {
        long now = clock();
        var r = SignedBundleVerifier.Verify(bundle, signatureJson, trust, "policy", now, store.LastBundleVersion("policy"));
        if (!r.Ok) return Audit("policy", r.Failure);
        var p = PolicyBundle.Parse(r.Bundle!);
        if (p is null) return Audit("policy", BundleFailure.Malformed);
        Policy = p; PolicySha256 = r.Bundle!.Sha256; PolicyExpiresMs = r.Bundle.ExpiresMs;
        store.AcceptBundle("policy", r.Bundle.BundleId, r.Bundle.Version, r.Bundle.Sha256, now, r.Bundle.ExpiresMs);
        return Audit("policy", BundleFailure.None, r.Bundle);
    }

    public BundleFailure AcceptIndicators(byte[] bundle, string signatureJson)
    {
        long now = clock();
        var r = SignedBundleVerifier.Verify(bundle, signatureJson, trust, "indicators", now, store.LastBundleVersion("indicators"));
        if (!r.Ok) return Audit("indicators", r.Failure);
        var parsed = IndicatorBundle.Parse(r.Bundle!);
        if (parsed is null) return Audit("indicators", BundleFailure.Malformed);
        store.Transact(() =>
        {
            foreach (var i in parsed.Indicators)
                store.UpsertIndicator(i.IndicatorId, i.Sha256, r.Bundle!.BundleId, r.Bundle.Sha256, now,
                    Math.Max(Math.Min(i.ValidUntilMs, r.Bundle.ExpiresMs), now + 1),
                    parsed.Revoked.Contains(i.IndicatorId) ? "revoked" : "verified");
            store.AcceptBundle("indicators", r.Bundle!.BundleId, r.Bundle.Version, r.Bundle.Sha256, now, r.Bundle.ExpiresMs);
        });
        return Audit("indicators", BundleFailure.None, r.Bundle);
    }

    private BundleFailure Audit(string type, BundleFailure f, VerifiedBundle? b = null)
    {
        store.Audit.Append(clock(), f == BundleFailure.None ? "BUNDLE_ACCEPTED" : "BUNDLE_REJECTED",
            JsonSerializer.Serialize(new { type, failure = f.ToString(), b?.BundleId, b?.Version, b?.Sha256 }));
        return f;
    }
}
