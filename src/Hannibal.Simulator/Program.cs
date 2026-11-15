// Hannibal Protocol - simulation drill.
// Runs the whole backend in one process against SYNTHETIC observations and
// writes the status snapshot the desktop app displays. Nothing on this
// machine is scanned, blocked, moved or changed. Works on any OS with .NET 10.
using Hannibal.Contracts;
using Hannibal.Core.Agents;
using Hannibal.Core.Deception;
using Hannibal.Core.Ipc;
using Hannibal.Fixtures;

if (args.Length == 1 && args[0] == "--deploy-decoys")
{
    // Used by deploy/install.ps1 -DeployDecoys (elevated). Windows only.
    if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("--deploy-decoys runs on Windows only."); return 2; }
    Hannibal.Windows.DecoyInstaller.Run(Hannibal.Windows.HostPaths.Default, Console.WriteLine);
    return 0;
}

if (args.Length == 2 && args[0] == "--remove-decoys")
{
    // Used by deploy/uninstall.ps1: removes decoys whose content is unchanged; leaves anything else alone.
    using var store = Hannibal.Core.Storage.HannibalStore.Open(args[1]);
    long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    var devices = store.Db.Query("SELECT DISTINCT device_id FROM canary_manifest").Select(r => (string)r[0]!).ToList();
    foreach (var d in devices)
    {
        var o = CanaryCleanup.RemoveAll(store, d, nowMs);
        Console.WriteLine($"Decoys on {d}: removed {o.Removed}, already gone {o.AlreadyGone}, kept because changed {o.KeptChanged}, failed {o.Failed}");
    }
    return 0;
}

string outDir = Path.GetFullPath(args.Length > 0 ? args[0] : "hannibal-drill");
Directory.CreateDirectory(outDir);
// The drill's clock starts at the real current time and is then advanced synthetically.
using var rig = new Rig(dir: Path.Combine(outDir, "state-" + Guid.NewGuid().ToString("N")[..8]),
    startMs: DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
void Say(string s) => Console.WriteLine(s);
void Step(string s) { Console.WriteLine(); Console.WriteLine("== " + s); }

Say("HANNIBAL PROTOCOL / SIMULATION ENVIRONMENT / synthetic drill - no system changes");

Step("Ambush: plan and register decoys");
var seed = new byte[32];
var plan = CanaryPlanner.Plan(Rig.Device, [@"C:\Users\demo\Documents", @"C:\Users\demo\Desktop"], seed);
rig.Runtime.RegisterCanaries(plan, "deployed");
Say($"{plan.Count} decoys registered (synthetic; no files written by the drill)");
string decoy = plan[0].Location;

Step("Benign baseline: a signed scanner reads a decoy");
rig.StartProcess(800, 0, "services.exe", "trusted");
rig.StartProcess(900, 800, "MsMpEng.exe", "trusted");
rig.Emit(CaptureChannels.EtwKernelFile, ObservationKinds.FileRead, "file|00c0ffee|decoy0",
    new() { ["process_key"] = Rig.Proc(900), ["path"] = decoy });
rig.Runtime.Pump();
Say($"Incidents after scanner read: {rig.Store.Count("incidents")} (expected 0)");

Step("Drill lineage: unsigned program started from the shell touches a decoy");
rig.StartProcess(4000, 0, "explorer.exe", "trusted");
rig.StartProcess(4001, 4000, "invoice_viewer.exe", "unsigned");
rig.StartProcess(4002, 4001, "helper.exe", "unsigned");
rig.Emit(CaptureChannels.EtwKernelFile, ObservationKinds.FileRename, "file|00c0ffee|decoy0",
    new() { ["process_key"] = Rig.Proc(4002), ["path"] = decoy });
rig.Emit(CaptureChannels.EtwKernelRegistry, ObservationKinds.PersistChange, @"persist|run_key|hkcu\...\run\updater",
    new() { ["process_key"] = Rig.Proc(4002) });
rig.Runtime.Pump();
Report();

Step("One connection on one channel: not enough for the network quorum");
const string endpoint = "tcp|v4|203.0.113.8|443|global";
rig.Emit(CaptureChannels.EtwKernelNetwork, ObservationKinds.NetConnect, endpoint, new() { ["process_key"] = Rig.Proc(4002) });
rig.Runtime.Pump();
Report();

Step("A second, separate connection seen on a second channel");
rig.Clock.Now += 3_000;
rig.Emit(CaptureChannels.Sysmon, ObservationKinds.NetConnect, endpoint, new() { ["process_key"] = Rig.Proc(4002) });
rig.Runtime.Pump();
Report();
Say("The ladder was already at Watch, so this evaluation climbed exactly one rung.");

Step("Signed indicator: the EICAR anti-malware TEST file hash");
const string eicarKey = "file|00c0ffee|000000000000000000000000000e1ca4";
const string eicarPath = @"C:\Users\demo\Downloads\eicar.com";
rig.Probe.Files[eicarPath] = new(eicarKey, Rig.EicarSha256, false);
rig.Emit(CaptureChannels.HashProbe, ObservationKinds.FileHash, eicarKey, new() { ["sha256"] = Rig.EicarSha256, ["path"] = eicarPath });
rig.Runtime.Pump();
rig.HeartbeatAll(); rig.Runtime.Tick();
Report();

var snap = StatusSnapshot.Build(rig.Runtime, rig.Clock.Now);
File.WriteAllText(Path.Combine(outDir, "snapshot.json"), snap.ToJson());

Step("Restoration: undo the simulated quarantine by its restore token");
var token = snap.Incidents.SelectMany(i => i.Actions).First(a => a.Type == "quarantine").RollbackToken!;
Say("Restore -> " + rig.Runtime.Restore(token).Code + "; repeated -> " + rig.Runtime.Restore(token).Code);

Step("Yielding: 16 minutes later the evidence is stale and the TTL has run out");
rig.Clock.Now += 16 * 60_000;
rig.HeartbeatAll(); rig.Broker.SweepExpired(); rig.Runtime.Tick();
Report();
Say("Broker intents:");
foreach (var i in rig.Broker.Intents()) Say($"  {i[1],-22} {i[3],-12} {i[2]}");

Step("Record");
Say($"Core audit chain: {rig.Store.Audit.Count()} entries, intact = {rig.Store.Audit.FirstBrokenLink() is null}");
Say($"Broker audit chain intact = {rig.Broker.AuditBrokenAt is null}");
Say("Snapshot for the desktop app: " + Path.Combine(outDir, "snapshot.json"));
Say("");
Say("This drill demonstrates decision logic on synthetic input. It is not evidence of real-world protection.");
return 0;

void Report()
{
    foreach (var i in StatusSnapshot.Build(rig.Runtime, rig.Clock.Now).Incidents.OrderBy(i => i.Label))
    {
        Say($"  {i.Label} {i.Status,-13} sev {i.Severity:0.00} conf {i.Confidence:0.00} -> {i.DecisionKind} [{i.ReasonCode}] rung {i.Rung}");
        Say($"     {i.Sentence}");
        foreach (var a in i.Actions) Say($"     action {a.Type} {a.State} (simulated) target {a.Target}");
    }
}
