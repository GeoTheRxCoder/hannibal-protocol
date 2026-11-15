using Hannibal.Contracts;
using Hannibal.Overwatch;

var policy = new SafeOverwatchPolicyEngine();
var id = Guid.NewGuid();
const long Now = 1_900_000_000_000L;
var ctx = new SafetyContext(Now, true, true, true);
string aHash = new string('a', 64);
string bHash = new string('b', 64);
var file = new TargetIdentity(TargetKind.FileOccurrence, "host-1", "file-occ-1",
    IsLocal: true, IsAuthorized: true, IsProtected: false, FileSha256: aHash);
var network = new TargetIdentity(TargetKind.NetworkEndpoint, "host-1",
    "tcp|203.0.113.8|443", IsLocal: true, IsAuthorized: true, IsProtected: false);

VerifiedIncident I(TargetIdentity target, double sev, double conf,
    VerifiedEvidenceFact[]? evidence = null, VerifiedMaliciousHashMatch[]? indicators = null)
    => new(id, "host-1", sev, conf, target, evidence ?? [], indicators ?? []);

VerifiedEvidenceFact E(string eid, EvidenceFamily family, string channel,
    string[] roots, long timestamp = Now) =>
    new(eid, family, "host-1", network.IdentityKey,
        channel, roots, timestamp, .96, TrustedIngestVerified: true);

VerifiedMaliciousHashMatch Match(string indicator, string observed) =>
    new("indicator-1", indicator, observed, file.IdentityKey,
        "host-1", "signed-bundle-1", SignatureVerified: true,
        IsRevoked: false, ValidUntilMs: Now + 60_000L);

void Expect(bool ok, string name)
{
    if (!ok) throw new Exception("FAIL " + name);
    Console.WriteLine("PASS " + name);
}

Expect(policy.Evaluate(I(file, .99, .99, indicators: [Match(bHash,aHash)]), ctx).Kind
    != DecisionKind.Quarantine, "Hash mismatch never authorizes quarantine");

Expect(policy.Evaluate(I(file, .99, .99, indicators: [Match(aHash,aHash)]), ctx).Kind
    == DecisionKind.Quarantine, "Exact signed indicator match qualifies");

Expect(policy.Evaluate(I(network,.99,.99,[
    E("raw",EvidenceFamily.Behavior, "etw", ["raw-1"])
]),ctx).Kind != DecisionKind.TemporaryNetworkBlock,
    "Single observation is not sufficient");

var sameRoot = new [] {
    E("finding-1",EvidenceFamily.Behavior,"etw-process",["raw-1"]),
    E("finding-2",EvidenceFamily.Behavior,"wfp-connection",["raw-1"])
};
Expect(policy.Evaluate(I(network,.99,.99,sameRoot),ctx).Kind
    != DecisionKind.TemporaryNetworkBlock,
    "Two derived findings sharing a root are one observation");

var differentRoots = new [] {
    E("finding-1",EvidenceFamily.Behavior,"etw-process",["raw-1"]),
    E("finding-2",EvidenceFamily.Behavior,"wfp-connection",["raw-2"])
};
Expect(policy.Evaluate(I(network,.95,.95,differentRoots),ctx).Kind
    == DecisionKind.TemporaryNetworkBlock, "Separate roots and channels qualify");

var graphDerived = new [] {
    E("finding-1",EvidenceFamily.Behavior,"etw-process",["raw-1"]),
    E("finding-2",EvidenceFamily.Graph,"wfp-connection",["raw-2"])
};
Expect(policy.Evaluate(I(network,.95,.95,graphDerived),ctx).Kind
    != DecisionKind.TemporaryNetworkBlock,
    "Graph inferences are not independent corroboration");

Expect(policy.Evaluate(I(network with {IsProtected=true},1,1,differentRoots),ctx).Kind
    != DecisionKind.TemporaryNetworkBlock, "Protected target is never contained");

Expect(policy.Evaluate(I(network with {IsAuthorized=false},1,1,differentRoots),ctx).Kind
    == DecisionKind.Deny, "Out-of-scope target is denied");

Expect(policy.Evaluate(I(network,.95,.95,differentRoots),
    ctx with {EssentialTelemetryHealthy=false}).Kind
    != DecisionKind.TemporaryNetworkBlock, "Missing telemetry blocks containment");

Expect(policy.Evaluate(I(network,.95,.95,differentRoots),
    ctx with {CalibrationVerified=false}).Kind
    != DecisionKind.TemporaryNetworkBlock, "Uncalibrated confidence blocks containment");

Expect(policy.Evaluate(I(network,.95,.95,[
    E("a",EvidenceFamily.Behavior,"etw",["raw-1"],Now-300_000L),
    E("b",EvidenceFamily.Behavior,"wfp",["raw-2"],Now-300_000L)
]),ctx).Kind != DecisionKind.TemporaryNetworkBlock,
    "Stale observations cannot authorize containment");

Console.WriteLine("All safety policy smoke checks passed.");
