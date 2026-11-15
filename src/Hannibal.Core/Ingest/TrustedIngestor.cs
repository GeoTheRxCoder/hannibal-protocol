using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hannibal.Contracts;
using Hannibal.Core.Storage;

namespace Hannibal.Core.Ingest;

public sealed record IngestResult(bool Accepted, string Code, long EventSeq = 0, string RootEventId = "");

/// <summary>
/// The ONLY component allowed to turn a collector's claim into a journal
/// event with a raw root ID. A collector must be registered (after the host
/// authenticated it) and must MAC every observation with its session key.
/// Observations of one underlying event from several sensors canonicalize to
/// the same root, so "two channels" never passes for "two events".
/// </summary>
public sealed class TrustedIngestor(HannibalStore store, string localDeviceId, Func<long> clock)
{
    public const long MaxFutureSkewMs = 5_000, MaxAgeMs = 600_000, HeartbeatWindowMs = 120_000;
    public static readonly string[] EssentialChannels =
        [CaptureChannels.EtwKernelProcess, CaptureChannels.EtwKernelNetwork, CaptureChannels.EtwKernelFile];

    private sealed class Collector(string channel, string sessionId, byte[] key)
    {
        public string Channel = channel, SessionId = sessionId;
        public byte[] Key = key;
        public long LastSeq, Lost, Rejected, LastSeenMs, LastLossMs = long.MinValue;
    }

    private readonly Dictionary<string, Collector> _collectors = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <summary>Called by the host only after it has authenticated the collector process.</summary>
    public void RegisterCollector(string collectorId, string channel, byte[] sessionKey)
    {
        if (sessionKey.Length < 32) throw new ArgumentException("Session key must be at least 256 bits");
        lock (_gate)
        {
            _collectors[collectorId] = new Collector(channel, Guid.NewGuid().ToString("N"), (byte[])sessionKey.Clone())
                { LastSeenMs = clock() };
            Persist(collectorId);
        }
    }

    public static string ComputeMac(byte[] key, string collectorId, string channel, string kind, string deviceId,
        string subjectKey, long observedMs, long seq, IReadOnlyDictionary<string, string> fields)
    {
        var sb = new StringBuilder();
        sb.Append(collectorId).Append('\u001f').Append(channel).Append('\u001f').Append(kind).Append('\u001f')
          .Append(deviceId).Append('\u001f').Append(subjectKey).Append('\u001f').Append(observedMs).Append('\u001f').Append(seq);
        foreach (var kv in fields.OrderBy(k => k.Key, StringComparer.Ordinal))
            sb.Append('\u001e').Append(kv.Key).Append('=').Append(kv.Value);
        return Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(sb.ToString())));
    }

    public IngestResult Ingest(RawObservation o)
    {
        lock (_gate)
        {
            long now = clock();
            if (!_collectors.TryGetValue(o.CollectorId, out var c)) return new(false, "UNKNOWN_COLLECTOR");
            IngestResult Reject(string code) { c.Rejected++; Persist(o.CollectorId); return new(false, code); }

            if (!StringComparer.Ordinal.Equals(c.Channel, o.CaptureChannel)) return Reject("CHANNEL_MISMATCH");
            if (!ObservationKinds.All.Contains(o.Kind)) return Reject("UNKNOWN_KIND");
            if (string.IsNullOrWhiteSpace(o.SubjectKey) || o.SubjectKey.Length > 512) return Reject("INVALID_SUBJECT");
            if (o.Fields is null || o.Fields.Count > 32 ||
                o.Fields.Any(f => f.Key.Length is 0 or > 64 || f.Value is null || f.Value.Length > 2048))
                return Reject("INVALID_FIELDS");
            var expect = ComputeMac(c.Key, o.CollectorId, o.CaptureChannel, o.Kind, o.DeviceId, o.SubjectKey,
                o.ObservedMs, o.CollectorSeq, o.Fields);
            if (o.MacHex is null || !CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expect), Encoding.ASCII.GetBytes(o.MacHex.ToLowerInvariant())))
                return Reject("BAD_MAC");
            if (!StringComparer.Ordinal.Equals(o.DeviceId, localDeviceId)) return Reject("FOREIGN_DEVICE");
            if (o.ObservedMs > now + MaxFutureSkewMs) return Reject("OBSERVED_IN_FUTURE");
            if (o.ObservedMs < now - MaxAgeMs) return Reject("STALE_OBSERVATION");
            if (o.CollectorSeq <= c.LastSeq) return Reject("DUPLICATE_OR_REORDERED");

            if (o.CollectorSeq > c.LastSeq + 1) { c.Lost += o.CollectorSeq - c.LastSeq - 1; c.LastLossMs = now; }
            c.LastSeq = o.CollectorSeq; c.LastSeenMs = now;

            o.Fields.TryGetValue("dedupe", out var dedupe);
            string root = HannibalStore.StableId("r", o.DeviceId, o.Kind, o.SubjectKey,
                (o.ObservedMs / 1000).ToString(), dedupe ?? "");
            string eventId = HannibalStore.StableId("evt", o.CollectorId, c.SessionId, o.CollectorSeq.ToString());
            long seq = store.AppendObservation(eventId, o.DeviceId, o.Kind, o.ObservedMs, now, o.SubjectKey,
                JsonSerializer.Serialize(o.Fields), root, o.CaptureChannel, o.CollectorId);
            Persist(o.CollectorId);
            return new(true, "ACCEPTED", seq, root);
        }
    }

    /// <summary>Collector liveness plus its own lost-event counter (e.g. ETW EventsLost).</summary>
    public void Heartbeat(string collectorId, long lostEventsDelta)
    {
        lock (_gate)
        {
            if (!_collectors.TryGetValue(collectorId, out var c)) return;
            long now = clock();
            c.LastSeenMs = now;
            if (lostEventsDelta > 0) { c.Lost += lostEventsDelta; c.LastLossMs = now; }
            Persist(collectorId);
        }
    }

    public string ChannelStatus(string channel, long nowMs)
    {
        lock (_gate)
        {
            var cs = _collectors.Values.Where(c => c.Channel == channel).ToList();
            if (cs.Count == 0 || cs.All(c => nowMs - c.LastSeenMs > HeartbeatWindowMs)) return "offline";
            return cs.Any(c => c.LastLossMs != long.MinValue && nowMs - c.LastLossMs <= HeartbeatWindowMs)
                ? "degraded" : "healthy";
        }
    }

    public bool EssentialTelemetryHealthy(long nowMs) =>
        EssentialChannels.All(ch => ChannelStatus(ch, nowMs) == "healthy");

    /// <summary>Fraction of essential channels that are healthy; feeds ML window coverage.</summary>
    public double Coverage(long nowMs) =>
        EssentialChannels.Count(ch => ChannelStatus(ch, nowMs) == "healthy") / (double)EssentialChannels.Length;

    private void Persist(string id)
    {
        var c = _collectors[id];
        long now = clock();
        store.SetCollectorHealth(id, c.Channel, c.LastSeq, c.LastSeenMs, c.Lost, c.Rejected, ChannelStatus(c.Channel, now));
    }
}

/// <summary>Helper for in-process collectors and tests: stamps sequence numbers and MACs.</summary>
public sealed class ObservationSigner(string collectorId, string channel, string deviceId, byte[] key)
{
    private long _seq;
    public string CollectorId => collectorId;
    public string Channel => channel;

    public RawObservation Make(string kind, string subjectKey, long observedMs, Dictionary<string, string>? fields = null)
    {
        fields ??= new();
        long seq = Interlocked.Increment(ref _seq);
        return new RawObservation(collectorId, channel, kind, deviceId, subjectKey, observedMs, seq, fields,
            TrustedIngestor.ComputeMac(key, collectorId, channel, kind, deviceId, subjectKey, observedMs, seq, fields));
    }

    /// <summary>Simulates events the sensor dropped (advances the sequence without emitting).</summary>
    public void SkipSequence(int count) => Interlocked.Add(ref _seq, count);
}
