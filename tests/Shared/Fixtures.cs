// Shared by the test runner and the simulator. NOT part of the product:
// product assemblies contain no signing code and no private keys.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hannibal.Contracts;
using Hannibal.Core.Agents;
using Hannibal.Core.Crypto;
using Hannibal.Core.Ingest;
using Hannibal.Core.Ipc;
using Hannibal.Core.Restoration;
using Hannibal.Core.Ribat;
using Hannibal.Core.Storage;

namespace Hannibal.Fixtures;

public sealed class TestSigner
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public TrustedKey Public { get; }
    public TestSigner()
    {
        var spki = _key.ExportSubjectPublicKeyInfo();
        Public = new TrustedKey(TrustRoot.ComputeKeyId(spki), SignedBundleVerifier.AlgEcdsa, spki);
    }
    public TrustRoot Root(int threshold = 1, params TestSigner[] others) =>
        new([Public, .. others.Select(o => o.Public)], threshold);

    public static byte[] Bundle(string type, string id, long version, long issuedMs, long expiresMs, object payload) =>
        JsonSerializer.SerializeToUtf8Bytes(new { bundle_type = type, bundle_id = id, version, issued_ms = issuedMs, expires_ms = expiresMs, payload });

    public string Sign(byte[] bundle, params TestSigner[] cosigners)
    {
        var sigs = new[] { this }.Concat(cosigners).Select(s => new
        {
            keyid = s.Public.KeyId, alg = SignedBundleVerifier.AlgEcdsa,
            sig = Convert.ToBase64String(s._key.SignData(bundle, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
        });
        return JsonSerializer.Serialize(new { signatures = sigs });
    }
}

public sealed class FakeClock(long startMs) { public long Now = startMs; public long Read() => Now; }

public sealed class FakeProbe : IFileProbe
{
    public readonly Dictionary<string, FileProbeResult> Files = new(StringComparer.OrdinalIgnoreCase);
    public FileProbeResult? Probe(string path) => Files.GetValueOrDefault(path);
}

/// <summary>A complete in-process deployment: store, ingestor, intake, broker and runtime, wired like the services.</summary>
public sealed class Rig : IDisposable
{
    public const string Device = "host-1";
    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    public readonly string Dir;
    public readonly FakeClock Clock;
    public readonly TestSigner Signer = new();
    public readonly FakeProbe Probe = new();
    public readonly byte[] SessionKey = RandomNumberGenerator.GetBytes(32);
    public HannibalStore Store;
    public TrustedIngestor Ingestor;
    public BundleIntake Intake;
    public SimulationBroker Broker;
    public CoreRuntime Runtime;
    public readonly Dictionary<string, ObservationSigner> Collectors = new();
    public bool BrokerOnline = true;

    public Rig(bool calibrationAttested = true, bool loadPolicy = true, string? dir = null, long startMs = 1_900_000_000_000L)
    {
        Clock = new FakeClock(startMs);
        Dir = dir ?? Path.Combine(Path.GetTempPath(), "hannibal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Dir);
        var trust = Signer.Root();
        Store = HannibalStore.Open(Path.Combine(Dir, "core.db"));
        Ingestor = new TrustedIngestor(Store, Device, Clock.Read);
        Intake = new BundleIntake(Store, trust, Clock.Read);
        Broker = NewBroker();
        var client = new BrokerClient(SessionKey, f => BrokerOnline ? Broker.Handle(f) : null, Clock.Read);
        Runtime = new CoreRuntime(Store, Ingestor, Intake, client, new ProtectedTargets(), new CoreOptions(Device), Clock.Read);

        foreach (var ch in new[] { CaptureChannels.EtwKernelProcess, CaptureChannels.EtwKernelNetwork, CaptureChannels.EtwKernelFile,
                     CaptureChannels.EtwKernelRegistry, CaptureChannels.Sysmon, CaptureChannels.HashProbe })
        {
            var key = RandomNumberGenerator.GetBytes(32);
            Ingestor.RegisterCollector("col-" + ch, ch, key);
            Collectors[ch] = new ObservationSigner("col-" + ch, ch, Device, key);
        }
        if (loadPolicy)
        {
            var (pb, ps) = PolicyBundle(1, calibrationAttested);
            Must(Intake.AcceptPolicy(pb, ps)); Must(Broker.LoadPolicy(pb, ps));
        }
        var (ib, isig) = IndicatorBundle(1);
        Must(Intake.AcceptIndicators(ib, isig)); Must(Broker.LoadIndicators(ib, isig));
    }

    public SimulationBroker NewBroker() =>
        new(Path.Combine(Dir, "broker.db"), SessionKey, Device, Signer.Root(), new ProtectedTargets(), Probe, Clock.Read);

    /// <summary>Simulates a broker process restart over the same private database.</summary>
    public void RestartBroker()
    {
        Broker.Dispose();
        Broker = NewBroker();
        var (pb, ps) = PolicyBundle(1, true); Broker.LoadPolicy(pb, ps);
        var (ib, isig) = IndicatorBundle(1); Broker.LoadIndicators(ib, isig);
    }

    public (byte[], string) PolicyBundle(long version, bool calibrationAttested)
    {
        // TEST FIXTURE: the calibration report hash refers to no real evaluation.
        var b = TestSigner.Bundle("policy", "fixture-policy", version, Clock.Now - 1000, Clock.Now + 86_400_000L, new
        {
            mode = "simulation", calibration_attested = calibrationAttested,
            calibration_report_sha256 = calibrationAttested ? new string('f', 64) : null
        });
        return (b, Signer.Sign(b));
    }

    public (byte[], string) IndicatorBundle(long version, string[]? revoked = null)
    {
        var b = TestSigner.Bundle("indicators", "fixture-indicators", version, Clock.Now - 1000, Clock.Now + 86_400_000L, new
        {
            indicators = new[] { new { indicator_id = "eicar-test-file", sha256 = EicarSha256 } },
            revoked = revoked ?? []
        });
        return (b, Signer.Sign(b));
    }

    public IngestResult Emit(string channel, string kind, string subject, Dictionary<string, string>? fields = null, long? atMs = null) =>
        Ingestor.Ingest(Collectors[channel].Make(kind, subject, atMs ?? Clock.Now, fields));

    public void HeartbeatAll() { foreach (var c in Collectors.Values) Ingestor.Heartbeat(c.CollectorId, 0); }

    public static string Proc(int pid) => $"proc|boot-1|{pid}|{133_000_000_000_000_000L + pid}|vol1-{pid:x8}";

    public IngestResult StartProcess(int pid, int parentPid, string image, string signer, string? sha = null) =>
        Emit(CaptureChannels.EtwKernelProcess, ObservationKinds.ProcessStart, Proc(pid), new()
        {
            ["parent_key"] = parentPid == 0 ? "" : Proc(parentPid), ["image_name"] = image,
            ["signer_status"] = signer, ["image_file_key"] = $"file|00c0ffee|{pid:x32}",
            ["image_sha256"] = sha ?? Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(image))),
            ["account_sid"] = "S-1-5-21-1-2-3-1001"
        });

    private static void Must(BundleFailure f) { if (f != BundleFailure.None) throw new InvalidOperationException("Fixture bundle rejected: " + f); }

    public void Dispose()
    {
        Broker.Dispose(); Store.Dispose();
        try { Directory.Delete(Dir, true); } catch (IOException) { }
    }
}
