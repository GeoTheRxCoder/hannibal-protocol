using System.Text.Json;
using Hannibal.Contracts;
using Hannibal.Core.Crypto;
using Hannibal.Core.Ingest;
using Hannibal.Core.Storage;
using Hannibal.Overwatch;

namespace Hannibal.Core.Relay;

public sealed record LoadedModel(KMeansAnomalyScorer Scorer, string ModelId, string FeatureSchema, bool ShadowOnly, string BundleSha256);

/// <summary>
/// "The Relay" (Scipio motif: study, adapt, hand on - under review). A model
/// is only ever loaded from a signed bundle. A candidate artifact
/// (is_candidate_only) loads in SHADOW: its scores are published for
/// comparison and carry no weight anywhere. No model has action authority.
/// </summary>
public static class SignedModelLoader
{
    public const string ExpectedSchema = "lineage-60s-v2";

    public static (LoadedModel? Model, string Code) Load(byte[] bundle, string signatureJson, TrustRoot trust,
        long nowMs, long lastVersion)
    {
        var r = SignedBundleVerifier.Verify(bundle, signatureJson, trust, "model", nowMs, lastVersion);
        if (!r.Ok) return (null, "BUNDLE_" + r.Failure.ToString().ToUpperInvariant());
        try
        {
            var p = r.Bundle!.Payload;
            if (p.GetProperty("feature_schema").GetString() != ExpectedSchema) return (null, "FEATURE_SCHEMA_MISMATCH");
            double[] Arr(string n) => p.GetProperty(n).EnumerateArray().Select(e => e.GetDouble()).ToArray();
            var centroids = p.GetProperty("centroids").EnumerateArray()
                .Select(c => c.EnumerateArray().Select(e => e.GetDouble()).ToArray()).ToArray();
            var caps = Arr("winsor_caps");
            if (caps.Length != 8) return (null, "DIMENSION_MISMATCH");
            var id = p.GetProperty("model_id").GetString()!;
            var scorer = new KMeansAnomalyScorer(id, caps, Arr("mean"), Arr("scale"), centroids, Arr("thresholds"),
                p.GetProperty("min_coverage").GetDouble());
            bool shadow = !p.TryGetProperty("is_candidate_only", out var c) || c.GetBoolean();
            return (new LoadedModel(scorer, id, ExpectedSchema, shadow, r.Bundle.Sha256), "OK");
        }
        catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException)
        {
            return (null, "MALFORMED_MODEL");
        }
    }
}

/// <summary>
/// "Unexpected axis" (Alps motif): an honest map of which approach routes are
/// watched. An unwatched axis is shown as unwatched, never implied covered.
/// </summary>
public static class AxisCoverage
{
    public static readonly (string Axis, string Channel)[] Axes =
    [
        ("process-creation", CaptureChannels.EtwKernelProcess),
        ("network-egress", CaptureChannels.EtwKernelNetwork),
        ("decoy-file-access", CaptureChannels.EtwKernelFile),
        ("registry-run-keys", CaptureChannels.EtwKernelRegistry),
        ("services", CaptureChannels.SecurityAudit),
        ("scheduled-tasks", CaptureChannels.SecurityAudit),
        ("wmi-subscriptions", CaptureChannels.Sysmon),
        ("os-denied-connections", CaptureChannels.WfpNetEvent),
    ];

    public static void Refresh(HannibalStore store, TrustedIngestor ingestor, string deviceId, long nowMs)
    {
        foreach (var (axis, channel) in Axes)
        {
            var status = ingestor.ChannelStatus(channel, nowMs) switch
            {
                "healthy" => "watched", "degraded" => "degraded", _ => "unwatched"
            };
            store.SetAxis(deviceId, axis, channel, status, nowMs);
        }
    }
}
