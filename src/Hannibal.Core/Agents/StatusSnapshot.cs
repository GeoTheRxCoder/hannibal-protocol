using System.Text.Json;
using System.Text.Json.Serialization;
using Hannibal.Contracts;
using Hannibal.Core.Analysis;
using Hannibal.Core.Ingest;

namespace Hannibal.Core.Agents;

public sealed record AgentView(string Name, string Health, string Detail, long LastEventSeq);
public sealed record ClaimView(string Text, bool IsHypothesis, List<string> RootEventIds, List<string> References);
public sealed record ActionView(string Type, string Target, string State, long? ExpiresMs, string? RollbackToken, bool Simulated);
public sealed record IncidentView(string IncidentId, string Label, string Status, double Severity, double Confidence,
    string TargetKind, string TargetKey, string DecisionKind, string ReasonCode, string Sentence, string Rung,
    long? RungExpiresMs, List<ClaimView> Claims, List<ActionView> Actions, long UpdatedMs);
public sealed record AxisView(string Axis, string Channel, string Status);
public sealed record GateView(string Name, string Status, string Detail);
public sealed record RelayView(string Stage, string Status, string Detail);
public sealed record BundleView(string Type, string BundleId, long Version, long ExpiresMs);

/// <summary>
/// Read-only picture PUSHED to the desktop app as a file. The UI holds no
/// command channel to the Core service or the broker in the beta.
/// </summary>
public sealed record StatusSnapshot(
    string Product, string Version, string Environment, string Mode, string Scope, long GeneratedMs,
    int DevicesInScope, int OpenInvestigations, int AgentsHealthy, int AgentsTotal,
    List<AgentView> Agents, List<IncidentView> Incidents, List<AxisView> Axes, List<GateView> TrustGates,
    List<RelayView> Relay, List<BundleView> Bundles, int DecoysDeployed, int DecoysTripped,
    string AuditHead, long AuditEntries, bool AuditIntact, List<string> Notices)
{
    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static StatusSnapshot Build(CoreRuntime rt, long nowMs, string version = "0.6.0-beta.1")
    {
        var store = rt.Store;
        string dev = rt.Options.DeviceId;
        var agents = store.ListHeartbeats().Select(r =>
        {
            string detail = "";
            try { detail = JsonDocument.Parse((string)r[4]!).RootElement.GetProperty("detail").GetString() ?? ""; }
            catch (Exception e) when (e is JsonException or KeyNotFoundException) { }
            // An agent that has not reported within two minutes is shown offline, whatever it last said.
            string health = nowMs - (long)r[1]! > 120_000 ? "offline" : (string)r[3]!;
            return new AgentView((string)r[0]!, health, detail, (long)r[2]!);
        }).ToList();

        var incidents = new List<IncidentView>();
        int n = 0;
        foreach (var i in store.ListIncidents(25))
        {
            var claims = new List<ClaimView>();
            if (store.LatestHypothesis(i.IncidentId) is string hj)
                foreach (var c in JsonSerializer.Deserialize<List<Claim>>(hj) ?? [])
                    claims.Add(new ClaimView(c.Text, c.IsHypothesis, c.RootEventIds.ToList(), c.References.ToList()));
            var d = store.LatestDecision(i.IncidentId);
            var ladder = store.GetLadder(i.DeviceId, i.CorrelationKey);
            var actions = store.ListContainment(i.IncidentId).Select(a => new ActionView(
                (string)a[1]!, (string)a[2]!, (string)a[3]!, (long?)a[4], (string?)a[5], true)).ToList();
            incidents.Add(new IncidentView(i.IncidentId, $"INC-{++n:0000}", i.Status, Math.Round(i.Severity, 3),
                Math.Round(i.Confidence, 3), i.TargetKind ?? "Process", i.TargetKey ?? i.CorrelationKey,
                d?.ActionType ?? "Observe", d?.ReasonCode ?? "NO_DECISION", Explain.DecisionSentence(d?.ReasonCode ?? ""),
                ((IsolationRung)(ladder?.Rung ?? 0)).ToString(), ladder?.ExpiresMs, claims, actions, i.UpdatedMs));
        }

        var axes = store.ListAxes(dev).Select(r => new AxisView((string)r[0]!, (string)r[1]!, (string)r[2]!)).ToList();
        bool telemetry = rt.Ingestor.EssentialTelemetryHealthy(nowMs);
        var collectors = store.ListCollectors();
        long? broken = store.Audit.FirstBrokenLink();
        var bundles = store.ListBundles().Select(r => new BundleView((string)r[0]!, (string)r[1]!, (long)r[2]!, (long)r[4]!)).ToList();

        var gates = new List<GateView>
        {
            new("OS observation", collectors.Count > 0 ? "Healthy" : "Review", $"{collectors.Count} capture channel(s) registered"),
            new("Authenticated collector", collectors.All(c => (long)c[5]! == 0) && collectors.Count > 0 ? "Healthy" : "Review",
                $"{collectors.Sum(c => (long)c[5]!)} rejected, {collectors.Sum(c => (long)c[4]!)} lost"),
            new("Trusted ingestion journal", telemetry ? "Healthy" : "Review", telemetry ? "Essential channels healthy" : "Essential channel offline or losing events"),
            new("Raw root record", broken is null ? "Healthy" : "High", broken is null ? "Hash chain intact" : $"Chain broken at entry {broken}"),
            new("Policy evaluator", rt.Intake.PolicyVerified ? "Healthy" : "Review", rt.Intake.PolicyVerified ? "Signed policy verified" : "No verified policy; actions declined"),
            new("Broker re-verification", "Info", "Simulation only. No system changes are made."),
        };

        var m = rt.Model;
        var relay = new List<RelayView>
        {
            new("Curate", "Info", "Training data is curated offline in ModelLab. Nothing is learned from live detections."),
            new("Evaluate", m is null ? "Review" : "Healthy", m is null ? "No evaluated model installed" : "Model " + m.ModelId),
            new("Shadow", m is { ShadowOnly: true } ? "Healthy" : "Info", m is { ShadowOnly: true } ? "Candidate scoring in shadow; scores carry no weight" : "No candidate in shadow"),
            new("Review", "Info", "Activation requires a signed release and a human decision."),
        };

        var canaries = store.ListCanaries(dev);
        var notices = new List<string>
        {
            "Simulation build. Detections are advisory and no containment action changes this device.",
            "Hannibal Protocol runs alongside Microsoft Defender. It does not replace it.",
            "Severity and confidence are uncalibrated ordering heuristics, not probabilities."
        };
        if (axes.Any(a => a.Status != "watched")) notices.Add($"{axes.Count(a => a.Status != "watched")} of {axes.Count} approach axes are not watched.");

        return new StatusSnapshot("Hannibal Protocol", version, rt.Options.Environment, rt.Options.Mode.ToString(),
            "This device only: " + dev, nowMs, 1,
            incidents.Count(i => i.Status is "open" or "investigating" or "contained"),
            agents.Count(a => a.Health == "healthy"), 7, agents, incidents, axes, gates, relay, bundles,
            canaries.Count(c => c.Status is "deployed" or "tripped"), canaries.Count(c => c.Status == "tripped"),
            store.Audit.Head(), store.Audit.Count(), broken is null, notices);
    }
}
