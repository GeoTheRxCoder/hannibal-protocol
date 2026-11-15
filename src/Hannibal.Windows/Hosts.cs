using System.Security.Cryptography;
using Hannibal.Core.Agents;
using Hannibal.Core.Crypto;
using Hannibal.Core.Deception;
using Hannibal.Core.Ingest;
using Hannibal.Core.Ipc;
using Hannibal.Core.Relay;
using Hannibal.Core.Restoration;
using Hannibal.Core.Ribat;
using Hannibal.Core.Storage;

namespace Hannibal.Windows;

public sealed record HostPaths(string Root)
{
    public const string PipeName = "HannibalProtocol.Broker.v1";
    public const string CoreServiceAccount = @"NT SERVICE\HannibalCore";
    public static HostPaths Default => new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Hannibal"));
    public string Core => Path.Combine(Root, "core");
    public string BrokerDir => Path.Combine(Root, "broker");
    public string Ipc => Path.Combine(Root, "ipc");
    public string Status => Path.Combine(Root, "status");
    public string Bundles => Path.Combine(Root, "bundles");
    public string SessionKey => Path.Combine(Ipc, "session.key");
    public string Snapshot => Path.Combine(Status, "snapshot.json");
    /// <summary>The trust root ships inside the signed installation directory, not in ProgramData.</summary>
    public static string TrustRootFile => Path.Combine(AppContext.BaseDirectory, "trust", "trust-root.json");

    public (byte[] Bundle, string Sig)? Read(string name)
    {
        string b = Path.Combine(Bundles, name + ".json"), s = b + ".sig";
        return File.Exists(b) && File.Exists(s) ? (File.ReadAllBytes(b), File.ReadAllText(s)) : null;
    }
}

/// <summary>Core service body: wires the tested Core runtime to Windows sensors and the broker pipe.</summary>
public static class CoreHost
{
    public static async Task RunAsync(HostPaths paths, IReadOnlyList<ICollectorSource> sources,
        Action<string> log, CancellationToken ct)
    {
        Directory.CreateDirectory(paths.Core); Directory.CreateDirectory(paths.Status);
        string device = MachineInfo.DeviceId();
        long Clock() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var trust = TrustRoot.Parse(File.ReadAllText(HostPaths.TrustRootFile));

        using var store = HannibalStore.Open(Path.Combine(paths.Core, "core.db"));
        var ingestor = new TrustedIngestor(store, device, Clock);
        var intake = new BundleIntake(store, trust, Clock);
        if (paths.Read("policy") is var (pb, ps)) log("Policy bundle: " + intake.AcceptPolicy(pb, ps));
        if (paths.Read("indicators") is var (ib, isig)) log("Indicator bundle: " + intake.AcceptIndicators(ib, isig));

        byte[] key = await WaitForKeyAsync(paths.SessionKey, log, ct);
        var broker = new BrokerClient(key, BrokerPipeClient.Transport(HostPaths.PipeName), Clock);
        var runtime = new CoreRuntime(store, ingestor, intake, broker, new ProtectedTargets(), new CoreOptions(device), Clock);

        if (paths.Read("model") is var (mb, ms))
        {
            var (model, code) = SignedModelLoader.Load(mb, ms, trust, Clock(), store.LastBundleVersion("model"));
            log("Model bundle: " + code);
            runtime.Model = model;
        }

        foreach (var src in sources)
        {
            var collectorKey = RandomNumberGenerator.GetBytes(32);
            ingestor.RegisterCollector(src.CollectorId, src.CaptureChannel, collectorKey);
            src.Start(new ObservationSigner(src.CollectorId, src.CaptureChannel, device, collectorKey),
                o => { var r = ingestor.Ingest(o); if (!r.Accepted) log("Rejected observation: " + r.Code); });
        }
        log($"Core running in SIMULATION mode on {device} with {sources.Count} collector(s).");

        long lastTick = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                runtime.Pump();
                if (Clock() - lastTick >= 15_000)
                {
                    foreach (var s in sources) ingestor.Heartbeat(s.CollectorId, s.TakeLostEvents());
                    runtime.Tick();
                    WriteSnapshot(paths.Snapshot, StatusSnapshot.Build(runtime, Clock()).ToJson());
                    lastTick = Clock();
                }
                await Task.Delay(1000, ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { foreach (var s in sources) s.Dispose(); }
    }

    private static async Task<byte[]> WaitForKeyAsync(string path, Action<string> log, CancellationToken ct)
    {
        for (int i = 0; ; i++)
        {
            try { if (File.Exists(path) && File.ReadAllBytes(path) is { Length: 32 } k) return k; }
            catch (IOException) { }
            if (i == 0) log("Waiting for the broker's session key...");
            await Task.Delay(2000, ct);
        }
    }

    /// <summary>Atomic replace, so the desktop app never reads a half-written file.</summary>
    private static void WriteSnapshot(string path, string json)
    {
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, path, overwrite: true);
    }
}

/// <summary>
/// Places decoys. Runs ELEVATED from the installer, not inside the Core
/// service: the Core's virtual account cannot (and should not) write into user
/// profile folders. The Core service only reads the resulting manifest.
/// </summary>
public static class DecoyInstaller
{
    public static int Run(HostPaths paths, Action<string> log)
    {
        Directory.CreateDirectory(paths.Core);
        string device = MachineInfo.DeviceId();
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        // The seed never leaves this machine; it only makes the plan reproducible.
        string seedFile = Path.Combine(paths.Core, "decoy.seed");
        byte[] seed = File.Exists(seedFile) ? File.ReadAllBytes(seedFile) : RandomNumberGenerator.GetBytes(32);
        if (!File.Exists(seedFile)) File.WriteAllBytes(seedFile, seed);
        using var store = HannibalStore.Open(Path.Combine(paths.Core, "core.db"));
        var plan = CanaryPlanner.Plan(device, CanaryDeployer.UserDocumentDirectories(), seed);
        var deployed = CanaryDeployer.Deploy(plan, seed);
        foreach (var d in deployed)
            store.UpsertCanary(new CanaryRow(d.Spec.CanaryId, device, d.Spec.DecoyKind, d.Spec.Location,
                d.FileIdentityKey, d.Sha256, d.Spec.SizeBytes, "deployed"), now);
        store.Audit.Append(now, "DECOYS_DEPLOYED", System.Text.Json.JsonSerializer.Serialize(new { planned = plan.Count, deployed = deployed.Count }));
        log($"Decoys deployed: {deployed.Count} of {plan.Count} planned (folders redirected to OneDrive are skipped).");
        return deployed.Count;
    }
}

/// <summary>Broker service body. Simulation only: it has no effector.</summary>
public static class BrokerHost
{
    public static async Task RunAsync(HostPaths paths, Action<string> log, CancellationToken ct)
    {
        SecureFiles.RestrictDirectory(paths.BrokerDir);
        SecureFiles.RestrictDirectory(paths.Ipc, HostPaths.CoreServiceAccount);
        byte[] key = SecureFiles.LoadOrCreateSessionKey(paths.SessionKey);
        var trust = TrustRoot.Parse(File.ReadAllText(HostPaths.TrustRootFile));
        long Clock() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        using var broker = new SimulationBroker(Path.Combine(paths.BrokerDir, "broker.db"), key, MachineInfo.DeviceId(),
            trust, new ProtectedTargets(), new FileIdentityProbe(), Clock);
        // The broker verifies the bundles itself. It never accepts the Core service's word that they are valid.
        if (paths.Read("policy") is var (pb, ps)) log("Policy bundle: " + broker.LoadPolicy(pb, ps));
        if (paths.Read("indicators") is var (ib, isig)) log("Indicator bundle: " + broker.LoadIndicators(ib, isig));

        var server = new BrokerPipeServer(HostPaths.PipeName, HostPaths.CoreServiceAccount, broker.Handle);
        log("Broker running in SIMULATION mode. No system changes will be made.");
        var sweep = Task.Run(async () =>
        {
            try { while (!ct.IsCancellationRequested) { broker.SweepExpired(); await Task.Delay(5000, ct); } }
            catch (OperationCanceledException) { }
        }, ct);
        try { await server.RunAsync(ct); } catch (OperationCanceledException) { }
        await sweep;
    }
}
