// Console test runner (no NuGet test framework, so it runs offline and in CI alike).
using System.Security.Cryptography;
using System.Text;
using Hannibal.Contracts;
using Hannibal.Core.Agents;
using Hannibal.Core.Analysis;
using Hannibal.Core.Crypto;
using Hannibal.Core.Deception;
using Hannibal.Core.Graph;
using Hannibal.Core.Identity;
using Hannibal.Core.Ingest;
using Hannibal.Core.Ipc;
using Hannibal.Core.Maneuver;
using Hannibal.Core.Relay;
using Hannibal.Core.Ribat;
using Hannibal.Core.Storage;
using Hannibal.Fixtures;

int passed = 0, failed = 0;
void Expect(bool ok, string name)
{
    if (ok) { passed++; Console.WriteLine("PASS " + name); }
    else { failed++; Console.WriteLine("FAIL " + name); }
}
void Section(string s) => Console.WriteLine("\n# " + s);
const string Endpoint = "tcp|v4|203.0.113.8|443|global";
string DecoyOf(Rig r)
{
    var plan = CanaryPlanner.Plan(Rig.Device, [@"C:\Users\demo\Documents"], new byte[32]);
    r.Runtime.RegisterCanaries(plan, "deployed");
    return plan[0].Location;
}
// Unsigned lineage 4001 -> 4002 started from the shell; 4002 renames a decoy.
void TripDecoy(Rig r)
{
    string decoy = DecoyOf(r);
    r.StartProcess(4000, 0, "explorer.exe", "trusted");
    r.StartProcess(4001, 4000, "invoice_viewer.exe", "unsigned");
    r.StartProcess(4002, 4001, "helper.exe", "unsigned");
    r.Emit(CaptureChannels.EtwKernelFile, ObservationKinds.FileRename, "file|00c0ffee|decoy0",
        new() { ["process_key"] = Rig.Proc(4002), ["path"] = decoy });
}
IngestResult Connect(Rig r, string channel, string endpoint = Endpoint) =>
    r.Emit(channel, ObservationKinds.NetConnect, endpoint, new() { ["process_key"] = Rig.Proc(4002) });
IncidentView Only(Rig r) => StatusSnapshot.Build(r.Runtime, r.Clock.Now).Incidents.Single();

Section("Identity keys");
{
    Expect(IdentityKeys.TryParseEndpoint(Endpoint, out var proto, out var ip, out var port) && proto == "tcp" && port == 443, "Endpoint key round-trips");
    Expect(!IdentityKeys.TryParseEndpoint("tcp|v4|203.0.113.008|443|global", out _, out _, out _), "Non-canonical endpoint spelling is rejected");
    Expect(!IdentityKeys.TryParseEndpoint("tcp|v4|203.0.113.8|443|private", out _, out _, out _), "Endpoint with a forged scope is rejected");
    Expect(IdentityKeys.Process("b1", 10, 5, "f1") != IdentityKeys.Process("b1", 10, 6, "f1"), "Reused PID with a new create time is a different process");
    bool threw = false; try { IdentityKeys.Process("b|1", 10, 5, "f1"); } catch (ArgumentException) { threw = true; }
    Expect(threw, "Identity parts cannot smuggle the key separator");
}

Section("Journal and store");
{
    using var r = new Rig();
    long a = r.Store.AppendObservation("e1", Rig.Device, "process.start", 1, 1, "s", "{}", "r1", "ch", "c");
    long b = r.Store.AppendObservation("e1", Rig.Device, "process.start", 1, 1, "s", "{}", "r1", "ch", "c");
    Expect(a == b && r.Store.Count("security_events") == 1, "Duplicate event id is idempotent");
    r.Store.SetOffset("x", 5, 1); r.Store.SetOffset("x", 3, 2);
    Expect(r.Store.GetOffset("x") == 5, "Consumer offset never moves backwards");
    bool rolledBack = false;
    try { r.Store.Transact(() => { r.Store.SetOffset("y", 9, 1); throw new InvalidOperationException(); }); }
    catch (InvalidOperationException) { rolledBack = r.Store.GetOffset("y") == 0; }
    Expect(rolledBack, "A failed transaction leaves no partial offset (crash-replay safe)");

    var inc = r.Store.OpenIncident(Rig.Device, "k", 1);
    Expect(r.Store.OpenIncident(Rig.Device, "k", 2) == inc, "Incident correlation key maps to one incident");
    r.Store.AddEvidence("raw-a", inc, null, Rig.Device, "s", "Behavior", "ch1", "p", 1, "verified", .9, ["root-1"]);
    r.Store.AddEvidence("raw-b", inc, null, Rig.Device, "s", "Behavior", "ch2", "p", 1, "verified", .9, ["root-2"]);
    r.Store.AddEvidence("graph-1", inc, null, Rig.Device, "s", "Graph", "derived", "p", 1, "unverified", .5, [], ["raw-a", "raw-b"]);
    Expect(r.Store.ResolveRoots("graph-1").SequenceEqual(["root-1", "root-2"]), "Derived finding inherits its parents' raw roots");
    bool cycle = false;
    try { r.Store.AddEvidence("raw-c", inc, null, Rig.Device, "s", "Behavior", "ch", "p", 1, "verified", .9, ["root-3"], ["raw-c"]); }
    catch (InvalidOperationException) { cycle = true; }
    Expect(cycle, "Self-derivation is rejected");
    Expect(r.Store.Audit.FirstBrokenLink() is null, "Audit chain verifies when untouched");
    r.Store.Db.Execute("UPDATE audit_chain SET body_json='{\"tampered\":true}' WHERE audit_seq=1");
    Expect(r.Store.Audit.FirstBrokenLink() == 1, "Audit chain detects an edited entry");
}

Section("Trusted ingestion");
{
    using var r = new Rig();
    var c = r.Collectors[CaptureChannels.EtwKernelNetwork];
    var good = c.Make(ObservationKinds.NetConnect, Endpoint, r.Clock.Now);
    Expect(r.Ingestor.Ingest(good).Accepted, "Authenticated observation is accepted");
    Expect(r.Ingestor.Ingest(good).Code == "DUPLICATE_OR_REORDERED", "Replayed observation is rejected");
    Expect(r.Ingestor.Ingest(c.Make(ObservationKinds.NetConnect, Endpoint, r.Clock.Now) with { MacHex = new string('0', 64) }).Code == "BAD_MAC", "Wrong MAC is rejected");
    Expect(r.Ingestor.Ingest(c.Make(ObservationKinds.NetConnect, Endpoint, r.Clock.Now) with { SubjectKey = "tcp|v4|198.51.100.1|443|global" }).Code == "BAD_MAC", "Altered subject fails the MAC");
    Expect(r.Ingestor.Ingest(c.Make(ObservationKinds.NetConnect, Endpoint, r.Clock.Now) with { CollectorId = "ghost" }).Code == "UNKNOWN_COLLECTOR", "Unregistered collector is rejected");
    Expect(r.Ingestor.Ingest(c.Make(ObservationKinds.NetConnect, Endpoint, r.Clock.Now) with { CaptureChannel = CaptureChannels.Sysmon }).Code == "CHANNEL_MISMATCH", "Collector cannot claim another channel");
    Expect(r.Ingestor.Ingest(c.Make(ObservationKinds.NetConnect, Endpoint, r.Clock.Now - 3_600_000)).Code == "STALE_OBSERVATION", "Stale observation is rejected");
    Expect(r.Ingestor.Ingest(c.Make(ObservationKinds.NetConnect, Endpoint, r.Clock.Now + 60_000)).Code == "OBSERVED_IN_FUTURE", "Future-dated observation is rejected");
    var foreign = new ObservationSigner("col-" + CaptureChannels.Sysmon, CaptureChannels.Sysmon, "host-2", new byte[32]);
    Expect(!r.Ingestor.Ingest(foreign.Make(ObservationKinds.NetConnect, Endpoint, r.Clock.Now)).Accepted, "Another device's observation is rejected");

    var k = r.Emit(CaptureChannels.EtwKernelNetwork, ObservationKinds.NetConnect, "tcp|v4|198.51.100.7|443|global");
    var s = r.Emit(CaptureChannels.Sysmon, ObservationKinds.NetConnect, "tcp|v4|198.51.100.7|443|global");
    Expect(k.RootEventId == s.RootEventId && k.EventSeq != s.EventSeq, "One event seen by two sensors canonicalizes to ONE raw root");
    using var h = new Rig();
    var hc = h.Collectors[CaptureChannels.EtwKernelNetwork];
    h.Ingestor.Ingest(hc.Make(ObservationKinds.NetConnect, Endpoint, h.Clock.Now));
    Expect(h.Ingestor.EssentialTelemetryHealthy(h.Clock.Now), "Telemetry healthy with all essential channels reporting");
    hc.SkipSequence(5);
    h.Ingestor.Ingest(hc.Make(ObservationKinds.NetConnect, Endpoint, h.Clock.Now));
    Expect(!h.Ingestor.EssentialTelemetryHealthy(h.Clock.Now), "A sequence gap (lost events) degrades telemetry health");
    h.Clock.Now += 121_000; h.HeartbeatAll();
    Expect(h.Ingestor.EssentialTelemetryHealthy(h.Clock.Now), "Health recovers after a clean heartbeat window");
}

Section("Signed bundles (logistics)");
{
    var s1 = new TestSigner(); var s2 = new TestSigner(); var outsider = new TestSigner();
    long now = 1_900_000_000_000L;
    var b = TestSigner.Bundle("policy", "p", 3, now - 10, now + 10_000, new { mode = "simulation" });
    var root = s1.Root();
    Expect(SignedBundleVerifier.Verify(b, s1.Sign(b), root, "policy", now, 0).Ok, "Valid signed bundle verifies");
    var t = (byte[])b.Clone(); t[^3] ^= 1;
    Expect(SignedBundleVerifier.Verify(t, s1.Sign(b), root, "policy", now, 0).Failure == BundleFailure.UnknownKeyOrBadSignature, "One flipped bit fails verification");
    Expect(SignedBundleVerifier.Verify(b, outsider.Sign(b), root, "policy", now, 0).Failure == BundleFailure.UnknownKeyOrBadSignature, "Signature by an unpinned key is rejected");
    Expect(SignedBundleVerifier.Verify(b, s1.Sign(b), root, "indicators", now, 0).Failure == BundleFailure.TypeMismatch, "Bundle of the wrong type is rejected");
    Expect(SignedBundleVerifier.Verify(b, s1.Sign(b), root, "policy", now + 20_000, 0).Failure == BundleFailure.Expired, "Expired bundle is rejected (freeze protection)");
    Expect(SignedBundleVerifier.Verify(b, s1.Sign(b), root, "policy", now, 4).Failure == BundleFailure.Rollback, "Older version is rejected (rollback protection)");
    var two = s1.Root(2, s2);
    Expect(SignedBundleVerifier.Verify(b, s1.Sign(b), two, "policy", now, 0).Failure == BundleFailure.ThresholdNotMet, "One signature does not meet a 2-key threshold");
    Expect(SignedBundleVerifier.Verify(b, s1.Sign(b, s1), two, "policy", now, 0).Failure == BundleFailure.ThresholdNotMet, "The same key signing twice counts once");
    Expect(SignedBundleVerifier.Verify(b, s1.Sign(b, s2), two, "policy", now, 0).Ok, "Two distinct pinned keys meet the threshold");
    Expect(SignedBundleVerifier.Verify(b, "{not json", root, "policy", now, 0).Failure == BundleFailure.Malformed, "Malformed signature file is rejected");

#pragma warning disable SYSLIB5006
    if (MLDsa.IsSupported)
    {
        using var ml = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var mlKey = new TrustedKey(TrustRoot.ComputeKeyId(ml.ExportSubjectPublicKeyInfo()), SignedBundleVerifier.AlgMlDsa65, ml.ExportSubjectPublicKeyInfo());
        string mlSig = System.Text.Json.JsonSerializer.Serialize(new { signatures = new[] { new { keyid = mlKey.KeyId, alg = SignedBundleVerifier.AlgMlDsa65, sig = Convert.ToBase64String(ml.SignData(b)) } } });
        Expect(SignedBundleVerifier.Verify(b, mlSig, new TrustRoot([mlKey], 1), "policy", now, 0).Ok, "ML-DSA-65 signature verifies (platform supports ML-DSA)");
        // Dual signing: ECDSA + ML-DSA under a 2-of-2 root.
        var both = System.Text.Json.JsonDocument.Parse(s1.Sign(b)).RootElement.GetProperty("signatures")[0];
        var dual = System.Text.Json.JsonSerializer.Serialize(new { signatures = new object[] { both, System.Text.Json.JsonDocument.Parse(mlSig).RootElement.GetProperty("signatures")[0] } });
        Expect(SignedBundleVerifier.Verify(b, dual, new TrustRoot([s1.Public, mlKey], 2), "policy", now, 0).Ok, "Dual ECDSA + ML-DSA signatures meet a 2-of-2 root");
    }
    else
    {
        var fakeMl = new TrustedKey("00ff00ff00ff00ff", SignedBundleVerifier.AlgMlDsa65, [1, 2, 3]);
        string sig = System.Text.Json.JsonSerializer.Serialize(new { signatures = new[] { new { keyid = "00ff00ff00ff00ff", alg = SignedBundleVerifier.AlgMlDsa65, sig = "AAAA" } } });
        Expect(SignedBundleVerifier.Verify(b, sig, new TrustRoot([fakeMl], 1), "policy", now, 0).Failure == BundleFailure.UnknownKeyOrBadSignature,
            "Where ML-DSA is unsupported, an ML-DSA signature never counts toward the threshold");
    }
#pragma warning restore SYSLIB5006

    using var r = new Rig();
    var (rb, rs) = r.IndicatorBundle(2, ["eicar-test-file"]);
    Expect(r.Intake.AcceptIndicators(rb, rs) == BundleFailure.None &&
           (string)r.Store.IndicatorsBySha(Rig.EicarSha256)[0][4]! == "revoked", "Revocation in a newer bundle is applied");
    var (ob, os) = r.IndicatorBundle(1);
    Expect(r.Intake.AcceptIndicators(ob, os) == BundleFailure.Rollback, "Intake refuses to go back to an older indicator bundle");
}

Section("Signed model loading (relay)");
{
    var s = new TestSigner(); long now = 1_900_000_000_000L;
    object Artifact(bool candidate, string schema = "lineage-60s-v2") => new
    {
        feature_schema = schema, model_id = "km-test", min_coverage = 0.9, is_candidate_only = candidate,
        winsor_caps = Enumerable.Repeat(10.0, 8), mean = Enumerable.Repeat(0.5, 8), scale = Enumerable.Repeat(1.0, 8),
        centroids = new[] { Enumerable.Repeat(0.0, 8) }, thresholds = new[] { 2.0 }
    };
    var cand = TestSigner.Bundle("model", "m", 1, now - 1, now + 9999, Artifact(true));
    var (m, code) = SignedModelLoader.Load(cand, s.Sign(cand), s.Root(), now, 0);
    Expect(m is { ShadowOnly: true } && code == "OK", "Signed candidate model loads in SHADOW only");
    Expect(SignedModelLoader.Load(cand, new TestSigner().Sign(cand), s.Root(), now, 0).Model is null, "Model signed by an unpinned key is not loaded");
    var bad = TestSigner.Bundle("model", "m", 1, now - 1, now + 9999, Artifact(false, "lineage-60s-v1"));
    Expect(SignedModelLoader.Load(bad, s.Sign(bad), s.Root(), now, 0).Code == "FEATURE_SCHEMA_MISMATCH", "Model for another feature schema is refused");
    var sc = m!.Scorer.Score([1000, 0, 0, 0, 0, 0, 0, 0], 1.0);
    Expect(sc.IsScorable && sc.ExceededTrainingCaps == 1, "A clipped feature spike is disclosed as out of training support");
    Expect(!m.Scorer.Score([1, 0, 0, 0, 0, 0, 0, 0], 0.5).IsScorable, "Low telemetry coverage makes a window unscorable, not benign");
}

Section("Broker IPC");
{
    var key = RandomNumberGenerator.GetBytes(32);
    var frame = FrameCodec.Seal(key, "{}"u8);
    Expect(FrameCodec.Open(key, frame) is not null, "Sealed frame opens with the session key");
    var t = (byte[])frame.Clone(); t[^1] ^= 1;
    Expect(FrameCodec.Open(key, t) is null, "Tampered frame is rejected");
    Expect(FrameCodec.Open(RandomNumberGenerator.GetBytes(32), frame) is null, "Frame under another key is rejected");
    bool big = false; try { FrameCodec.Seal(key, new byte[70_000]); } catch (InvalidDataException) { big = true; }
    Expect(big, "Oversized frame is refused");
    var g = new ReplayGuard();
    BrokerRequest R(long counter, string nonce, long issued, long life = 10_000) =>
        new(1, "r", counter, issued, issued + life, nonce, "GetStatus", new());
    string n1 = new('a', 32), n2 = new('b', 32), n3 = new('c', 32);
    Expect(g.Check(R(1, n1, 1000), 1000) is null, "Fresh request passes the replay guard");
    Expect(g.Check(R(1, n2, 1000), 1000) == "COUNTER_REPLAY", "Reused counter is rejected");
    Expect(g.Check(R(2, n1, 1000), 1000) == "NONCE_REPLAY", "Reused nonce is rejected");
    Expect(g.Check(R(3, n3, 1000), 20_000) == "REQUEST_EXPIRED", "Expired request is rejected");
    Expect(g.Check(R(4, n3, 1000, 600_000), 1000) == "INVALID_LIFETIME", "Over-long request lifetime is rejected");
}

Section("Containment broker (the Ribat)");
{
    using var r = new Rig();
    var client = r.Runtime.Broker;
    Dictionary<string, string> Block(string idem, string target = Endpoint, string ttl = "600", string device = Rig.Device, string? policy = null) => new()
    {
        ["decision_id"] = "d1", ["idempotency_key"] = idem, ["device_id"] = device, ["target_key"] = target,
        ["ttl_seconds"] = ttl, ["policy_sha256"] = policy ?? r.Intake.PolicySha256!
    };
    Expect(client.Send(BrokerCommand.SimulateNetworkBlock, Block("k1", device: "host-2")).Code == "OUTSIDE_AUTHORIZED_SCOPE", "Cross-device target is denied by the broker");
    Expect(client.Send(BrokerCommand.SimulateNetworkBlock, Block("k1", ttl: "901")).Code == "INVALID_TTL", "TTL above 900 s is denied");
    Expect(client.Send(BrokerCommand.SimulateNetworkBlock, Block("k1", target: "tcp|v4|192.168.1.1|443|private")).Code == "PROTECTED_TARGET", "Local gateway range is a protected target");
    Expect(client.Send(BrokerCommand.SimulateNetworkBlock, Block("k1", target: "udp|v4|9.9.9.9|53|global")).Code == "PROTECTED_TARGET", "DNS port is a protected target");
    Expect(client.Send(BrokerCommand.SimulateNetworkBlock, Block("k1", target: "cmd.exe /c whoami")).Code == "INVALID_ENDPOINT", "Free-form text is not a target (no command runner)");
    Expect(client.Send(BrokerCommand.SimulateNetworkBlock, Block("k1", policy: new string('0', 64))).Code == "POLICY_MISMATCH", "Request citing a policy the broker did not verify is denied");
    var ok = client.Send(BrokerCommand.SimulateNetworkBlock, Block("k1"));
    Expect(ok is { Ok: true, Simulated: true, RollbackToken: not null }, "Valid request is applied as a SIMULATED action with a restore token");
    var again = client.Send(BrokerCommand.SimulateNetworkBlock, Block("k1"));
    Expect(again.Code == "IDEMPOTENT_REPLAY" && again.ActionId == ok.ActionId && r.Broker.Intents().Count == 1, "Repeated idempotency key performs nothing new");
    Expect(client.Send(BrokerCommand.SimulateNetworkBlock, Block("k1", target: "tcp|v4|203.0.113.9|443|global")).Code == "IDEMPOTENCY_KEY_REUSED", "Idempotency key cannot be reused for another target");
    Expect(client.Send(BrokerCommand.Rollback, new() { ["rollback_token"] = "nope" }).Code == "UNKNOWN_ROLLBACK_TOKEN", "Unknown restore token is denied");
    Expect(client.Send(BrokerCommand.Rollback, new() { ["rollback_token"] = ok.RollbackToken! }).Code == "ROLLED_BACK" &&
           client.Send(BrokerCommand.Rollback, new() { ["rollback_token"] = ok.RollbackToken! }).Code == "ALREADY_ROLLED_BACK", "Rollback is idempotent");

    // Quarantine re-verification.
    const string fkey = "file|00c0ffee|0000000000000000000000000000beef", path = @"C:\Users\demo\Downloads\eicar.com";
    Dictionary<string, string> Q(string idem, string sha = Rig.EicarSha256, string p = path) => new()
    {
        ["decision_id"] = "d2", ["idempotency_key"] = idem, ["device_id"] = Rig.Device, ["target_key"] = fkey,
        ["sha256"] = sha, ["path"] = p, ["policy_sha256"] = r.Intake.PolicySha256!
    };
    Expect(client.Send(BrokerCommand.SimulateQuarantine, Q("q1")).Code == "HANDLE_BINDING_UNAVAILABLE", "No handle binding => quarantine denied");
    r.Probe.Files[path] = new(fkey, new string('b', 64), false);
    Expect(client.Send(BrokerCommand.SimulateQuarantine, Q("q1")).Code == "FILE_HASH_CHANGED", "File re-hash mismatch => quarantine denied");
    r.Probe.Files[path] = new("file|00c0ffee|other", Rig.EicarSha256, false);
    Expect(client.Send(BrokerCommand.SimulateQuarantine, Q("q1")).Code == "FILE_IDENTITY_CHANGED", "File identity swap => quarantine denied");
    r.Probe.Files[path] = new(fkey, Rig.EicarSha256, true);
    Expect(client.Send(BrokerCommand.SimulateQuarantine, Q("q1")).Code == "PROTECTED_PUBLISHER", "File signed by a protected publisher => denied");
    r.Probe.Files[path] = new(fkey, Rig.EicarSha256, false);
    Expect(client.Send(BrokerCommand.SimulateQuarantine, Q("q1", sha: new string('c', 64))).Code == "NO_VALID_SIGNED_INDICATOR", "Hash absent from the broker's own signed bundle => denied");
    Expect(client.Send(BrokerCommand.SimulateQuarantine, Q("q1", p: @"C:\Windows\System32\kernel32.dll")).Code == "PROTECTED_TARGET", "OS file path => denied");
    Expect(client.Send(BrokerCommand.SimulateQuarantine, Q("q1", p: @"C:\Users\demo\..\..\Windows\x.dll")).Code == "PROTECTED_TARGET", "Path traversal => denied");
    // The preceding requests count toward the per-minute rate limit; move past the window.
    r.Clock.Now += 61_000;
    Expect(client.Send(BrokerCommand.SimulateQuarantine, Q("q1")).Ok, "Exact signed match with bound handle => simulated quarantine");
    Expect(r.Broker.AuditBrokenAt is null, "Broker audit chain is intact");

    // Rate limit.
    r.Clock.Now += 61_000;
    string last = "";
    for (int i = 0; i < 12; i++) last = client.Send(BrokerCommand.SimulateNetworkBlock, Block("rl-" + i, target: $"tcp|v4|203.0.113.{20 + i}|443|global")).Code;
    Expect(last == "RATE_LIMITED", "Burst of new actions is rate limited");
}

{
    using var r = new Rig();
    // Raw frames: forged command names and unauthenticated frames.
    byte[] Raw(string command, long counter) => FrameCodec.Seal(r.SessionKey, FrameCodec.Encode(new BrokerRequest(
        1, "raw", counter, r.Clock.Now, r.Clock.Now + 5000, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)), command, new())));
    string CodeOf(byte[]? reply) => FrameCodec.Decode<BrokerResponse>(FrameCodec.Open(r.SessionKey, reply!)!)!.Code;
    Expect(CodeOf(r.Broker.Handle(Raw("1", 1000))) == "UNKNOWN_COMMAND", "Numeric command value is not accepted as a command");
    Expect(CodeOf(r.Broker.Handle(Raw("RunShell", 1001))) == "UNKNOWN_COMMAND", "Unknown command is denied");
    Expect(r.Broker.Handle(FrameCodec.Seal(RandomNumberGenerator.GetBytes(32), "{}"u8)) is null, "Frame without the session key gets no reply");

}

Section("Broker crash consistency");
{
    foreach (var step in new[] { "after-intent", "after-effect" })
    {
        using var r = new Rig();
        var bargs = new Dictionary<string, string>
        {
            ["decision_id"] = "d1", ["idempotency_key"] = "crash-" + step, ["device_id"] = Rig.Device,
            ["target_key"] = Endpoint, ["ttl_seconds"] = "600", ["policy_sha256"] = r.Intake.PolicySha256!
        };
        r.Broker.FaultInjector = s => s == step;
        bool crashed = false;
        try { r.Runtime.Broker.Send(BrokerCommand.SimulateNetworkBlock, bargs); } catch (BrokerCrashException) { crashed = true; }
        r.RestartBroker();
        var state = (string)r.Broker.Intents().Single()[3]!;
        Expect(crashed && state == "FAILED_ON_CRASH", $"Crash {step}: intent fails closed on restart, nothing left half-applied");
        var retry = r.Runtime.Broker.Send(BrokerCommand.SimulateNetworkBlock, bargs);
        Expect(retry.Code == "IDEMPOTENT_REPLAY" && !retry.Ok && r.Broker.Intents().Count == 1, $"Crash {step}: retry with the same key does not double-apply");
    }
    using var r2 = new Rig();
    var a2 = new Dictionary<string, string>
    {
        ["decision_id"] = "d1", ["idempotency_key"] = "ttl", ["device_id"] = Rig.Device,
        ["target_key"] = Endpoint, ["ttl_seconds"] = "60", ["policy_sha256"] = r2.Intake.PolicySha256!
    };
    r2.Runtime.Broker.Send(BrokerCommand.SimulateNetworkBlock, a2);
    r2.Clock.Now += 61_000;
    r2.RestartBroker();
    Expect((string)r2.Broker.Intents().Single()[3]! == "EXPIRED", "Restart after the TTL marks the action expired (automatic cleanup)");
    var replayed = FrameCodec.Seal(r2.SessionKey, FrameCodec.Encode(new BrokerRequest(1, "old", 1, r2.Clock.Now, r2.Clock.Now + 5000, new string('d', 32), "GetStatus", new())));
    Expect(FrameCodec.Decode<BrokerResponse>(FrameCodec.Open(r2.SessionKey, r2.Broker.Handle(replayed)!)!)!.Code == "COUNTER_REPLAY", "Replay counter survives a broker restart");
}

Section("The Maneuver (isolation ladder)");
{
    long t = 1000;
    var m1 = IsolationLadder.Next(null, DecisionKind.TemporaryNetworkBlock, t);
    Expect(m1.State.Rung == IsolationRung.Watch, "A block decision climbs ONE rung from Observe, not two");
    var m2 = IsolationLadder.Next(m1.State, DecisionKind.TemporaryNetworkBlock, t + 1);
    Expect(m2.State.Rung == IsolationRung.EnvelopEgress, "The next evaluation reaches the egress envelope");
    Expect(IsolationLadder.Next(m2.State, DecisionKind.TemporaryNetworkBlock, t + 2).State.Rung == IsolationRung.EnvelopEgress, "A block decision never reaches Hold");
    Expect(m2.State.ExpiresMs - m2.State.EnteredMs <= 900_000, "Envelope TTL is capped at 900 s");
    var down = IsolationLadder.Next(m2.State, DecisionKind.Alert, m2.State.ExpiresMs + 1);
    Expect(down.State.Rung == IsolationRung.Watch && down.Reason == "TTL_EXPIRED_STEP_DOWN", "Expired envelope yields one rung when support is gone");
    Expect(IsolationLadder.Next(null, DecisionKind.Quarantine, t).State.Rung == IsolationRung.Hold, "Exact signed-indicator match may enter Hold directly");
    Expect(IsolationLadder.Next(null, DecisionKind.Deny, t).State.Rung == IsolationRung.Observe, "Deny never climbs");
}

Section("Ambush (decoys)");
{
    var seed = RandomNumberGenerator.GetBytes(32);
    var p1 = CanaryPlanner.Plan("d", [@"C:\Users\a\Documents"], seed);
    var p2 = CanaryPlanner.Plan("d", [@"C:\Users\a\Documents"], seed);
    Expect(p1.SequenceEqual(p2), "Decoy plan is deterministic for a device seed");
    Expect(p1.All(c => c.SizeBytes > 1024) && p1.Select(c => c.SizeBytes).Distinct().Count() > 1, "Decoys are larger than 1 KiB and vary in size");
    var pdf = CanaryPlanner.Render(p1.First(c => c.Extension == ".pdf"), seed);
    Expect(Encoding.ASCII.GetString(pdf, 0, 5) == "%PDF-", "Rendered decoy carries the right magic number");
    Expect(!CanaryClassifier.Classify(ObservationKinds.FileRead, "MsMpEng.exe", "trusted").IsTripwire, "Defender reading a decoy is expected");
    Expect(CanaryClassifier.Classify(ObservationKinds.FileRead, "MsMpEng.exe", "unsigned").IsTripwire, "An unsigned process NAMED like a scanner still trips");
    Expect(CanaryClassifier.Classify(ObservationKinds.FileWrite, "x.exe", "unsigned").Confidence > CanaryClassifier.Classify(ObservationKinds.FileDelete, "explorer.exe", "trusted").Confidence, "Shell deletion by the user scores below an unsigned write");
}

{
    using var r = new Rig();
    var seed = RandomNumberGenerator.GetBytes(32);
    var plan = CanaryPlanner.Plan(Rig.Device, [r.Dir], seed);
    foreach (var spec in plan.Take(3)) File.WriteAllBytes(spec.Location, CanaryPlanner.Render(spec, seed));
    foreach (var spec in plan.Take(3))
        r.Store.UpsertCanary(new CanaryRow(spec.CanaryId, Rig.Device, spec.DecoyKind, spec.Location, null,
            Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(spec.Location))), spec.SizeBytes, "deployed"), r.Clock.Now);
    File.WriteAllText(plan[1].Location, "the user saved their own file here");
    File.Delete(plan[2].Location);
    var o = CanaryCleanup.RemoveAll(r.Store, Rig.Device, r.Clock.Now);
    Expect(o.Removed == 1 && o.KeptChanged == 1 && o.AlreadyGone == 1 && !File.Exists(plan[0].Location) && File.Exists(plan[1].Location),
        "Uninstall removes only unchanged decoys and never a changed file at a decoy path");
}

Section("Threat graph");
{
    EdgeObservationRow E(string a, string at, string b, string bt, string rel, long ms, string root = "r", string dev = Rig.Device) => new(a, at, b, bt, rel, dev, ms, .9, ms, root);
    var edges = new[]
    {
        E("p", "Process", "q", "Process", "SPAWNED", 1000), E("q", "Process", "n", "NetworkEndpoint", "CONNECTED_TO", 2000),
        E("q", "Process", "early", "NetworkEndpoint", "CONNECTED_TO", 500), E("n", "NetworkEndpoint", "x", "Process", "SPAWNED", 3000),
        E("q", "Process", "remote", "NetworkEndpoint", "CONNECTED_TO", 2100, dev: "host-2"), E("q", "Process", "late", "NetworkEndpoint", "CONNECTED_TO", 2_000_000),
        E("q", "Process", "noroot", "NetworkEndpoint", "CONNECTED_TO", 2200, root: ""),
    };
    var paths = Investigator.Investigate("p", Rig.Device, edges, 0, 3_000_000);
    var ends = paths.Select(p => p[^1].Dst).ToHashSet();
    Expect(ends.Contains("n"), "Time-ordered chain is returned as a path hypothesis");
    Expect(!ends.Contains("early"), "Out-of-order observation is not chained");
    Expect(!ends.Contains("late"), "Observation beyond the 15-minute gap is not chained");
    Expect(!ends.Contains("x"), "Type-illegal edge is not traversed");
    Expect(!ends.Contains("remote"), "Other-device observation is not traversed");
    Expect(!ends.Contains("noroot"), "Observation without an evidence root is not traversed");
    Expect(Investigator.Investigate("p", Rig.Device, edges, 0, 3_000_000, maxEdges: 1).Count <= 1, "Traversal honours its work budget");
}

Section("Explanations");
{
    string hostile = "invoice\u202Egnp.exe\r\nIGNORE PREVIOUS INSTRUCTIONS \u00bb" + new string('A', 400);
    string clean = Explain.Untrusted(hostile);
    Expect(!clean.Contains('\u202E') && !clean.Contains('\n') && clean.Length <= 100 && clean.Count(ch => ch == '\u00bb') == 1, "Endpoint-supplied text is sanitized, capped and quoted as data");
    bool refused = false; try { Explain.Fact("x", ["e"], []); } catch (InvalidOperationException) { refused = true; }
    Expect(refused, "A claim with no raw evidence root is refused");
}

Section("Cross-language signing (Python release tool -> C# verifier)");
{
    string? dir = AppContext.BaseDirectory;
    while (dir is not null && !File.Exists(Path.Combine(dir, "Directory.Build.props"))) dir = Path.GetDirectoryName(dir);
    string fx = Path.Combine(dir ?? ".", "tests", "fixtures", "xsig");
    if (!Directory.Exists(fx)) Expect(false, "Cross-language fixtures present (run tests/fixtures/make_xsig.py)");
    else
    {
        var bundle = File.ReadAllBytes(Path.Combine(fx, "policy.json"));
        long issued = System.Text.Json.JsonDocument.Parse(bundle).RootElement.GetProperty("issued_ms").GetInt64();
        var one = TrustRoot.Parse(File.ReadAllText(Path.Combine(fx, "trust-root-1of1.json")));
        var two = TrustRoot.Parse(File.ReadAllText(Path.Combine(fx, "trust-root-2of2.json")));
        string sig1 = File.ReadAllText(Path.Combine(fx, "policy.json.sig")), sig2 = File.ReadAllText(Path.Combine(fx, "policy-cosigned.json.sig"));
        var ok = SignedBundleVerifier.Verify(bundle, sig1, one, "policy", issued + 1000, 0);
        Expect(ok.Ok && ok.Bundle!.BundleId == "xsig-policy", "Bundle signed by the Python tool verifies in C#");
        Expect(Hannibal.Core.Restoration.PolicyBundle.Parse(ok.Bundle!) is { Mode: "simulation", CalibrationAttested: false }, "Python-built policy parses as simulation, uncalibrated");
        Expect(SignedBundleVerifier.Verify(bundle, sig1, two, "policy", issued + 1000, 0).Failure == BundleFailure.ThresholdNotMet, "One Python signature does not meet a 2-of-2 root");
        Expect(SignedBundleVerifier.Verify(bundle, sig2, two, "policy", issued + 1000, 0).Ok, "Two Python co-signatures meet a 2-of-2 root");
        var tampered = (byte[])bundle.Clone(); tampered[tampered.Length / 2] ^= 0x20;
        Expect(!SignedBundleVerifier.Verify(tampered, sig1, one, "policy", issued + 1000, 0).Ok, "Tampered Python-signed bundle is rejected in C#");
        bool badRoot = false;
        try { TrustRoot.Parse(File.ReadAllText(Path.Combine(fx, "trust-root-1of1.json")).Replace("\"threshold\": 1", "\"threshold\": 3")); }
        catch (FormatException) { badRoot = true; }
        Expect(badRoot, "Trust root with an impossible threshold is refused");
    }
}

Section("End-to-end decision safety (seven agents, simulation)");
{
    using (var r = new Rig())
    {
        string decoy = DecoyOf(r);
        r.StartProcess(800, 0, "services.exe", "trusted"); r.StartProcess(900, 800, "MsMpEng.exe", "trusted");
        r.Emit(CaptureChannels.EtwKernelFile, ObservationKinds.FileRead, "file|x|y", new() { ["process_key"] = Rig.Proc(900), ["path"] = decoy });
        r.Runtime.Pump();
        Expect(r.Store.Count("incidents") == 0, "Scanner read of a decoy opens no incident");
    }
    using (var r = new Rig())
    {
        TripDecoy(r); r.Runtime.Pump();
        var i = Only(r);
        Expect(i.DecisionKind == "Alert" && i.Actions.Count == 0, "A tripped decoy alone alerts and contains nothing");
        Expect(i.Claims.All(c => c.RootEventIds.Count > 0), "Every explanation claim cites raw evidence roots");
        Connect(r, CaptureChannels.EtwKernelNetwork); r.Runtime.Pump();
        Expect(Only(r).DecisionKind == "Alert", "One connection on one channel does not authorize a block");
    }
    using (var r = new Rig())
    {
        TripDecoy(r); Connect(r, CaptureChannels.EtwKernelNetwork); Connect(r, CaptureChannels.Sysmon); r.Runtime.Pump();
        Expect(Only(r).DecisionKind == "Alert" && r.Broker.Intents().Count == 0, "The SAME event on two channels (one raw root) does not authorize a block");
    }
    using (var r = new Rig())
    {
        TripDecoy(r); Connect(r, CaptureChannels.EtwKernelNetwork); r.Clock.Now += 3000; Connect(r, CaptureChannels.EtwKernelNetwork); r.Runtime.Pump();
        Expect(Only(r).DecisionKind == "Alert", "Two events on ONE channel do not authorize a block");
    }
    using (var r = new Rig())
    {
        TripDecoy(r); Connect(r, CaptureChannels.EtwKernelNetwork); r.Clock.Now += 3000; Connect(r, CaptureChannels.Sysmon); r.Runtime.Pump();
        var i = Only(r);
        Expect(i.DecisionKind == "TemporaryNetworkBlock" && i.Rung == "Watch" && r.Broker.Intents().Count == 0, "Two roots on two channels qualify; the ladder climbs one rung first");
        r.HeartbeatAll(); r.Runtime.Tick(); i = Only(r);
        Expect(i.Rung == "EnvelopEgress" && i.Actions.Single() is { State: "executed", Simulated: true }, "Next evaluation: SIMULATED egress block, TTL bound");
        Expect((string)r.Broker.Intents().Single()[3]! == "APPLIED", "Broker recorded exactly one simulated intent");
        r.HeartbeatAll(); r.Runtime.Tick();
        Expect(r.Broker.Intents().Count == 1, "Re-evaluation does not issue a second action");
        var graph = r.Store.GetEvidence(i.IncidentId).Single(e => e.Family == "Graph");
        var rawRoots = r.Store.GetEvidence(i.IncidentId).Where(e => e.Family == "Behavior").SelectMany(e => e.ResolvedRoots).ToHashSet();
        Expect(graph.ResolvedRoots.Count > 0 && graph.ResolvedRoots.All(rawRoots.Contains), "Graph finding shares the raw roots it was derived from");
        r.Clock.Now += 16 * 60_000; r.HeartbeatAll(); r.Broker.SweepExpired(); r.Runtime.Tick(); i = Only(r);
        Expect(i.DecisionKind == "Alert" && i.Rung == "Watch" && i.Actions.Single().State == "expired" && i.Status == "investigating", "Stale evidence + expired TTL: the envelope yields and the action expires");
        Expect(r.Store.Audit.FirstBrokenLink() is null && r.Broker.AuditBrokenAt is null, "Both audit chains are intact after the full scenario");
    }
    using (var r = new Rig(calibrationAttested: false))
    {
        TripDecoy(r); Connect(r, CaptureChannels.EtwKernelNetwork); r.Clock.Now += 3000; Connect(r, CaptureChannels.Sysmon); r.Runtime.Pump();
        Expect(Only(r).DecisionKind == "Alert", "Without attested calibration (the shipping default) nothing is blocked");
    }
    using (var r = new Rig(loadPolicy: false))
    {
        TripDecoy(r); Connect(r, CaptureChannels.EtwKernelNetwork); r.Clock.Now += 3000; Connect(r, CaptureChannels.Sysmon); r.Runtime.Pump();
        Expect(Only(r).ReasonCode is "DEGRADED_TRUST_OR_TELEMETRY" or "PROTECTED_TARGET", "Without a verified signed policy new actions are declined");
    }
    using (var r = new Rig())
    {
        TripDecoy(r); Connect(r, CaptureChannels.EtwKernelNetwork); r.Clock.Now += 3000;
        r.Collectors[CaptureChannels.EtwKernelFile].SkipSequence(3);
        r.Emit(CaptureChannels.EtwKernelFile, ObservationKinds.FileRead, "file|a|b", new() { ["path"] = "x" });
        Connect(r, CaptureChannels.Sysmon); r.Runtime.Pump();
        Expect(Only(r).ReasonCode == "DEGRADED_TRUST_OR_TELEMETRY", "Lost telemetry declines new actions and raises a health condition");
    }
    using (var r = new Rig())
    {
        TripDecoy(r);
        Connect(r, CaptureChannels.EtwKernelNetwork, "tcp|v4|192.168.1.1|443|private"); r.Clock.Now += 3000;
        Connect(r, CaptureChannels.Sysmon, "tcp|v4|192.168.1.1|443|private"); r.Runtime.Pump();
        Expect(Only(r).ReasonCode == "PROTECTED_TARGET", "A protected endpoint is never selected for containment");
    }
    using (var r = new Rig())
    {
        r.BrokerOnline = false;
        TripDecoy(r); Connect(r, CaptureChannels.EtwKernelNetwork); r.Clock.Now += 3000; Connect(r, CaptureChannels.Sysmon);
        r.Runtime.Pump(); r.HeartbeatAll(); r.Runtime.Tick();
        var i = Only(r);
        Expect(i.Actions.Single().State == "failed" && i.Status != "contained", "Broker outage: the action is recorded as failed, never assumed applied");
    }
    using (var r = new Rig())
    {
        const string fkey = "file|00c0ffee|0000000000000000000000000000beef", path = @"C:\Users\demo\Downloads\eicar.com";
        r.Probe.Files[path] = new(fkey, Rig.EicarSha256, false);
        r.Emit(CaptureChannels.HashProbe, ObservationKinds.FileHash, fkey, new() { ["sha256"] = Rig.EicarSha256, ["path"] = path });
        r.Runtime.Pump();
        var i = Only(r);
        Expect(i.DecisionKind == "Quarantine" && i.Rung == "Hold" && i.Actions.Single().Type == "quarantine", "EICAR test hash in a signed bundle => SIMULATED quarantine");
        var restore = r.Runtime.Restore(i.Actions.Single().RollbackToken!);
        Expect(restore.Ok && Only(r).Status == "resolved" && Only(r).Actions.Single().State == "rolled_back", "Restore token undoes the action and closes the incident");
    }
    using (var r = new Rig())
    {
        const string fkey = "file|00c0ffee|0000000000000000000000000000beef";
        r.Emit(CaptureChannels.HashProbe, ObservationKinds.FileHash, fkey, new() { ["sha256"] = new string('9', 64), ["path"] = @"C:\Users\demo\a.exe" });
        r.Runtime.Pump();
        Expect(r.Store.Count("incidents") == 0, "A hash that is not in the signed bundle raises nothing");
        var (rb, rs) = r.IndicatorBundle(2, ["eicar-test-file"]); r.Intake.AcceptIndicators(rb, rs);
        r.Emit(CaptureChannels.HashProbe, ObservationKinds.FileHash, fkey, new() { ["sha256"] = Rig.EicarSha256, ["path"] = @"C:\Users\demo\a.exe" });
        r.Runtime.Pump();
        Expect(r.Store.Count("incidents") == 0, "A REVOKED indicator raises nothing");
    }
    using (var r = new Rig())
    {
        // A model-only anomaly: non-shadow model, 31-day baseline, no other evidence.
        var s = new TestSigner();
        var art = TestSigner.Bundle("model", "m", 1, r.Clock.Now - 1, r.Clock.Now + 99_999_999, new
        {
            feature_schema = "lineage-60s-v2", model_id = "km-fixture", min_coverage = 0.9, is_candidate_only = false,
            winsor_caps = Enumerable.Repeat(5.0, 8), mean = Enumerable.Repeat(0.0, 8), scale = Enumerable.Repeat(1.0, 8),
            centroids = new[] { Enumerable.Repeat(0.0, 8) }, thresholds = new[] { 0.5 }
        });
        r.Runtime.Model = SignedModelLoader.Load(art, s.Sign(art), s.Root(), r.Clock.Now, 0).Model;
        r.Store.BaselineStartedMs(Rig.Device, r.Clock.Now - 31L * 24 * 3600 * 1000);
        r.StartProcess(4000, 0, "explorer.exe", "trusted"); r.StartProcess(5001, 4000, "burst.exe", "unsigned");
        for (int k = 0; k < 40; k++) r.StartProcess(5100 + k, 5001, "w.exe", "unsigned");
        r.Runtime.Pump(); r.Clock.Now += 61_000; r.HeartbeatAll(); r.Runtime.Tick(); r.HeartbeatAll(); r.Runtime.Tick();
        var all = StatusSnapshot.Build(r.Runtime, r.Clock.Now).Incidents;
        Expect(all.Count > 0 && all.All(i => i.DecisionKind == "Alert" && i.Actions.Count == 0) && r.Broker.Intents().Count == 0, "ML anomaly alone => triage alert, never containment");
    }
    using (var r = new Rig())
    {
        // Same burst, but before the 30-day baseline exists: the window is unscorable.
        r.StartProcess(4000, 0, "explorer.exe", "trusted"); r.StartProcess(5001, 4000, "burst.exe", "unsigned");
        r.Runtime.Pump(); r.Clock.Now += 61_000; r.HeartbeatAll(); r.Runtime.Tick();
        Expect(r.Store.Count("incidents") == 0 && (long)r.Store.Db.Scalar("SELECT COUNT(*) FROM feature_windows WHERE anomaly_ratio IS NULL")! > 0, "No 30-day baseline => window recorded as unscorable, not zero");
    }
    {
        using var r = new Rig();
        bool refused = false;
        try { _ = new CoreRuntime(r.Store, r.Ingestor, r.Intake, r.Runtime.Broker, new ProtectedTargets(), new CoreOptions(Rig.Device, OperatingMode.Enforcing), r.Clock.Read); }
        catch (NotSupportedException) { refused = true; }
        Expect(refused, "Enforcing mode cannot be started in the beta");
    }
    using (var r = new Rig())
    {
        TripDecoy(r); r.Runtime.Pump(); r.HeartbeatAll(); r.Runtime.Tick();
        var snap = StatusSnapshot.Build(r.Runtime, r.Clock.Now);
        Expect(snap.Mode == "Simulation" && snap.AgentsTotal == 7 && snap.Agents.Count == 7 && snap.Notices.Count >= 3, "Status snapshot always states mode, scope and limits");
        Expect(snap.Axes.Any(a => a.Status == "unwatched"), "Unwatched approach axes are reported as unwatched");
        var back = System.Text.Json.JsonSerializer.Deserialize<StatusSnapshot>(snap.ToJson(), StatusSnapshot.Json);
        Expect(back is not null && back.Incidents.Count == snap.Incidents.Count && back.Incidents[0].Claims.Count == snap.Incidents[0].Claims.Count
               && back.Mode == "Simulation", "Status snapshot round-trips through JSON (the dashboard's input contract)");
        Expect(!snap.ToJson().Contains("Accounts_Reconciliation") && !snap.ToJson().Contains("Contracts_Signed"), "Decoy file names never appear in the world-readable snapshot");
        long before = r.Store.Count("evidence_records");
        r.Store.SetOffset(CoreRuntime.Consumer, 0, r.Clock.Now); // cannot rewind (monotonic), so replay via a fresh consumer is a no-op
        r.Runtime.Pump();
        Expect(r.Store.Count("evidence_records") == before, "Pipeline does not duplicate findings on a repeated pump");
    }
}

Console.WriteLine($"\n{passed} passed, {failed} failed");
return failed == 0 ? 0 : 1;
