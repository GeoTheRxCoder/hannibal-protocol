namespace Hannibal.Contracts;

/// <summary>Capture channels. A channel names ONE sensor path into the OS.</summary>
public static class CaptureChannels
{
    public const string EtwKernelProcess = "etw-kernel-process";
    public const string EtwKernelFile = "etw-kernel-file";
    public const string EtwKernelNetwork = "etw-kernel-network";
    public const string EtwKernelRegistry = "etw-kernel-registry";
    public const string SecurityAudit = "evtlog-security-audit";
    public const string Sysmon = "sysmon-operational";
    public const string WfpNetEvent = "wfp-net-event";
    public const string HashProbe = "file-hash-probe";
}

public static class ObservationKinds
{
    public const string ProcessStart = "process.start";
    public const string ProcessStop = "process.stop";
    public const string NetConnect = "net.connect";
    public const string NetDenied = "net.denied";
    public const string FileRead = "file.read";
    public const string FileWrite = "file.write";
    public const string FileRename = "file.rename";
    public const string FileDelete = "file.delete";
    public const string FileHash = "file.hash";
    public const string PersistChange = "persist.change";
    public const string DecoyTouch = "decoy.touch";
    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        ProcessStart, ProcessStop, NetConnect, NetDenied, FileRead, FileWrite,
        FileRename, FileDelete, FileHash, PersistChange, DecoyTouch
    };
}

/// <summary>
/// One OS observation as claimed by a collector. Nothing in it is trusted
/// until the trusted ingestor has authenticated the collector and the MAC.
/// </summary>
public sealed record RawObservation(
    string CollectorId,
    string CaptureChannel,
    string Kind,
    string DeviceId,
    string SubjectKey,
    long ObservedMs,
    long CollectorSeq,
    IReadOnlyDictionary<string, string> Fields,
    string MacHex);

public enum OperatingMode { Simulation, Enforcing }

/// <summary>Cannae ladder rungs. Each rung is bounded by a TTL and steps down on expiry.</summary>
public enum IsolationRung { Observe = 0, Watch = 1, EnvelopEgress = 2, Hold = 3 }
