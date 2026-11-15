// UNVERIFIED ON WINDOWS. This file was written without access to the
// TraceEvent package or a Windows machine. Before relying on it:
//   1. confirm each provider GUID with `logman query providers`;
//   2. capture a short trace and confirm the event IDs and payload field
//      names used below (they differ between Windows builds);
//   3. run the collector acceptance tests in docs/BETA_TEST_PLAN.md.
// Real-time kernel-provider sessions need administrator rights.
using System.Collections.Concurrent;
using System.Net;
using Hannibal.Contracts;
using Hannibal.Core.Identity;
using Hannibal.Core.Ingest;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace Hannibal.Windows.Etw;

/// <summary>One real-time ETW session per capture channel, so lost-event counts are per channel.</summary>
public sealed class EtwProviderCollector(
    string collectorId, string channel, Guid provider, ulong keywords,
    Func<TraceEvent, (string Kind, string Subject, Dictionary<string, string> Fields)?> map) : ICollectorSource
{
    private TraceEventSession? _session;
    private long _lostReported;

    public string CollectorId => collectorId;
    public string CaptureChannel => channel;

    public void Start(ObservationSigner signer, Action<RawObservation> emit)
    {
        string name = "Hannibal-RT-" + channel;
        // A named session outlives a crashed process: stop a stale one before starting.
        TraceEventSession.GetActiveSession(name)?.Stop(true);
        _session = new TraceEventSession(name) { StopOnDispose = true };
        _session.EnableProvider(provider, TraceEventLevel.Informational, keywords);
        _session.Source.Dynamic.All += e =>
        {
            try
            {
                if (map(e) is var (kind, subject, fields))
                    emit(signer.Make(kind, subject, new DateTimeOffset(e.TimeStamp.ToUniversalTime()).ToUnixTimeMilliseconds(), fields));
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or InvalidCastException or IndexOutOfRangeException)
            {
                // A payload we cannot interpret is dropped and counted as lost, never guessed at.
                Interlocked.Decrement(ref _lostReported);
            }
        };
        new Thread(() => _session.Source.Process()) { IsBackground = true, Name = name }.Start();
    }

    public long TakeLostEvents()
    {
        long total = _session?.EventsLost ?? 0;
        long delta = total - Interlocked.Exchange(ref _lostReported, total);
        return Math.Max(0, delta);
    }

    public void Dispose() => _session?.Dispose();
}

public static class EtwCollectors
{
    private static readonly Guid KernelProcess = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");
    private static readonly Guid KernelFile = new("EDD08927-9CC4-4E65-B970-C2560FB5C289");
    private static readonly Guid KernelNetwork = new("7DD42A49-5329-4832-8DFD-43D979153A88");
    private static readonly Guid KernelRegistry = new("70EB4F03-C1DE-4F73-A051-33D13D5413BD");

    /// <summary>pid -> identity key of the most recently started process with that pid.</summary>
    private static readonly ConcurrentDictionary<int, string> Live = new();

    private static readonly ConcurrentDictionary<string, (string FileKey, string Sha, string Signer)> ImageCache = new();

    /// <summary>Identity, hash and signer of an image, cached by path and last-write time (hashing is expensive).</summary>
    private static (string FileKey, string Sha, string Signer) ImageFacts(string path)
    {
        if (path.Length == 0 || !File.Exists(path)) return ("", "", "unknown");
        string cacheKey = path.ToLowerInvariant() + "|" + File.GetLastWriteTimeUtc(path).Ticks;
        return ImageCache.GetOrAdd(cacheKey, _ =>
        {
            if (ImageCache.Count > 4096) ImageCache.Clear();
            var probe = new FileIdentityProbe().Probe(path);
            return (probe?.FileIdentityKey ?? "", probe?.Sha256 ?? "", Authenticode.Status(path));
        });
    }

    public static IReadOnlyList<ICollectorSource> Create(string bootId, Func<IReadOnlySet<string>> decoyPaths)
    {
        string ProcKey(int pid) => Live.TryGetValue(pid, out var k) ? k : "";

        var process = new EtwProviderCollector("etw-process", CaptureChannels.EtwKernelProcess, KernelProcess, 0x10 /* PROCESS */, e =>
        {
            if ((int)e.ID != 1) return null; // ProcessStart
            int pid = Convert.ToInt32(e.PayloadByName("ProcessID"));
            int ppid = Convert.ToInt32(e.PayloadByName("ParentProcessID"));
            long create = ((DateTime)e.PayloadByName("CreateTime")).ToFileTimeUtc();
            string path = DevicePaths.ToDosPath(Convert.ToString(e.PayloadByName("ImageName")) ?? "");
            string parent = ProcKey(ppid); // resolved at the child's start time, before the pid can be reused
            var (fileKey, sha, signer) = ImageFacts(path);
            string key = IdentityKeys.Process(bootId, pid, create, fileKey.Length > 0 ? fileKey.Replace('|', ':') : "unknown-image");
            Live[pid] = key;
            return (ObservationKinds.ProcessStart, key, new Dictionary<string, string>
            {
                ["parent_key"] = parent, ["image_name"] = Path.GetFileName(path), ["image_file_key"] = fileKey,
                ["image_sha256"] = sha, ["signer_status"] = signer,
                ["reported_ppid"] = ppid.ToString()
            });
        });

        var network = new EtwProviderCollector("etw-network", CaptureChannels.EtwKernelNetwork, KernelNetwork, 0x10 | 0x20 /* IPv4 | IPv6 */, e =>
        {
            if ((int)e.ID is not (12 or 28)) return null; // TCP connection attempted (v4 / v6)
            int pid = Convert.ToInt32(e.PayloadByName("PID"));
            var raw = e.PayloadByName("daddr");
            var ip = raw is byte[] b ? new IPAddress(b) : new IPAddress(BitConverter.GetBytes(Convert.ToUInt32(raw)));
            int port = (ushort)IPAddress.NetworkToHostOrder((short)Convert.ToUInt16(e.PayloadByName("dport")));
            return (ObservationKinds.NetConnect, IdentityKeys.Endpoint("tcp", ip, port),
                new Dictionary<string, string> { ["process_key"] = ProcKey(pid) });
        });

        // Only decoy paths are forwarded: Kernel-File is far too busy to journal wholesale.
        var file = new EtwProviderCollector("etw-file", CaptureChannels.EtwKernelFile, KernelFile, 0x10 | 0x80 | 0x400 | 0x800, e =>
        {
            string path = DevicePaths.ToDosPath(Convert.ToString(e.PayloadByName("FileName")) ?? "");
            if (path.Length == 0 || !decoyPaths().Contains(path)) return null;
            string kind = (int)e.ID switch
            {
                19 or 27 => ObservationKinds.FileRename,
                26 => ObservationKinds.FileDelete,
                16 or 17 => ObservationKinds.FileWrite,
                _ => ObservationKinds.FileRead
            };
            return (kind, "decoy|" + path.ToLowerInvariant(),
                new Dictionary<string, string> { ["process_key"] = ProcKey(e.ProcessID), ["path"] = path });
        });

        var registry = new EtwProviderCollector("etw-registry", CaptureChannels.EtwKernelRegistry, KernelRegistry, 0x100 /* SET_VALUE_KEY */, e =>
        {
            string keyName = Convert.ToString(e.PayloadByName("KeyName")) ?? "";
            if (!keyName.Contains(@"\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)) return null;
            string value = Convert.ToString(e.PayloadByName("ValueName")) ?? "";
            return (ObservationKinds.PersistChange, IdentityKeys.Persistence("run_key", keyName + "\\" + value),
                new Dictionary<string, string> { ["process_key"] = ProcKey(e.ProcessID), ["axis"] = "run_key" });
        });

        return [process, network, file, registry];
    }
}
