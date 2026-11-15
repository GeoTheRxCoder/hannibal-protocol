using System.Security.Cryptography;
using System.Text.Json;
using Hannibal.Core.Crypto;
using Hannibal.Core.Identity;
using Hannibal.Core.Ipc;
using Hannibal.Core.Storage;

namespace Hannibal.Core.Ribat;

/// <summary>What the broker independently learns about a file by opening it itself.</summary>
public sealed record FileProbeResult(string FileIdentityKey, string Sha256, bool SignedByProtectedPublisher);

/// <summary>Opens by stable identity, hashes the SAME handle, reads signer. Null = handle binding not possible.</summary>
public interface IFileProbe { FileProbeResult? Probe(string path); }

/// <summary>
/// "The Ribat" (Abu Yusuf Ya'qub al-Mansur motif: the fortified post and the
/// reserve held back until the main line has verified). The Containment
/// Broker trusts nothing it is told. It authenticates the frame, rejects
/// replays, re-derives scope and protected-target rules, verifies the signed
/// policy and indicator bundles from ITS OWN copies, re-hashes the file, writes
/// an intent before acting and can always roll back.
///
/// BETA: this broker has no effector that changes the system. Every action is
/// recorded as simulated. There is no code path here that blocks traffic,
/// moves a file or terminates a process.
/// </summary>
public sealed class SimulationBroker : IDisposable
{
    public const int MaxTtlSeconds = 900, MaxActiveBlocks = 20, MaxActionsPerMinute = 10;

    private readonly SqliteDb _db;
    private readonly AuditChain _audit;
    private readonly byte[] _sessionKey;
    private readonly string _deviceId;
    private readonly Func<long> _clock;
    private readonly ProtectedTargets _protected;
    private readonly IFileProbe _probe;
    private readonly TrustRoot _trust;
    private readonly ReplayGuard _replay;
    private readonly Dictionary<string, (string IndicatorId, long ValidUntilMs)> _indicators = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private string? _policySha256;
    private long _policyExpiresMs;

    /// <summary>Test hook: return true to simulate a crash at the named step.</summary>
    public Func<string, bool>? FaultInjector { get; set; }

    public SimulationBroker(string dbPath, byte[] sessionKey, string deviceId, TrustRoot trust,
        ProtectedTargets protectedTargets, IFileProbe probe, Func<long> clock)
    {
        _db = SqliteDb.Open(dbPath);
        _db.Exec(HannibalStore.ReadSchema("broker_001.sql"));
        _audit = new AuditChain(_db);
        _sessionKey = sessionKey; _deviceId = deviceId; _trust = trust;
        _protected = protectedTargets; _probe = probe; _clock = clock;
        _replay = new ReplayGuard { LastCounter = Kv("replay_counter") };
        Recover();
    }

    public string AuditHead => _audit.Head();
    public long? AuditBrokenAt => _audit.FirstBrokenLink();

    // ---- Trust material: verified here, from the broker's own copies -------

    public BundleFailure LoadPolicy(byte[] bundle, string signatureJson)
    {
        lock (_gate)
        {
            var r = SignedBundleVerifier.Verify(bundle, signatureJson, _trust, "policy", _clock(), Kv("bundle:policy"));
            if (!r.Ok) return r.Failure;
            _policySha256 = r.Bundle!.Sha256; _policyExpiresMs = r.Bundle.ExpiresMs;
            SetKv("bundle:policy", r.Bundle.Version);
            _audit.Append(_clock(), "POLICY_ACCEPTED", Json(new { r.Bundle.BundleId, r.Bundle.Version, r.Bundle.Sha256 }));
            return BundleFailure.None;
        }
    }

    public BundleFailure LoadIndicators(byte[] bundle, string signatureJson)
    {
        lock (_gate)
        {
            var r = SignedBundleVerifier.Verify(bundle, signatureJson, _trust, "indicators", _clock(), Kv("bundle:indicators"));
            if (!r.Ok) return r.Failure;
            var b = r.Bundle!;
            var parsed = Restoration.IndicatorBundle.Parse(b);
            if (parsed is null) return BundleFailure.Malformed;
            _indicators.Clear();
            foreach (var i in parsed.Indicators.Where(i => !parsed.Revoked.Contains(i.IndicatorId)))
                _indicators[i.Sha256] = (i.IndicatorId, Math.Min(i.ValidUntilMs, b.ExpiresMs));
            SetKv("bundle:indicators", b.Version);
            _audit.Append(_clock(), "INDICATORS_ACCEPTED", Json(new { b.BundleId, b.Version, Count = _indicators.Count }));
            return BundleFailure.None;
        }
    }

    // ---- Request handling --------------------------------------------------

    /// <summary>Returns a sealed reply frame, or null when the request frame is not authentic.</summary>
    public byte[]? Handle(byte[] frame)
    {
        lock (_gate)
        {
            var body = FrameCodec.Open(_sessionKey, frame);
            if (body is null) { _audit.Append(_clock(), "REJECTED_FRAME", "{\"code\":\"BAD_MAC\"}"); return null; }
            var req = FrameCodec.Decode<BrokerRequest>(body);
            if (req is null || req.Args is null) return Reply(new BrokerResponse("", false, "MALFORMED_REQUEST"));
            long now = _clock();
            var replay = _replay.Check(req, now);
            if (replay is not null) return Reply(Denied(req, replay));
            SetKv("replay_counter", req.Counter);

            // Names only: a numeric string must not select a command.
            if (!Enum.GetNames<BrokerCommand>().Contains(req.Command, StringComparer.Ordinal))
                return Reply(Denied(req, "UNKNOWN_COMMAND"));
            var resp = Enum.Parse<BrokerCommand>(req.Command) switch
            {
                BrokerCommand.GetStatus => new BrokerResponse(req.RequestId, true, "OK", State: StatusJson()),
                BrokerCommand.SimulateNetworkBlock => NetworkBlock(req, now),
                BrokerCommand.SimulateQuarantine => Quarantine(req, now),
                BrokerCommand.Rollback => Rollback(req, now),
                _ => Denied(req, "UNKNOWN_COMMAND")
            };
            return Reply(resp);
        }
    }

    private BrokerResponse NetworkBlock(BrokerRequest req, long now)
    {
        var a = req.Args;
        if (!Common(req, now, out var deny, out var decisionId, out var idem, out var target)) return deny!;
        if (!IdentityKeys.TryParseEndpoint(target, out _, out _, out _)) return Denied(req, "INVALID_ENDPOINT");
        if (_protected.IsProtectedEndpointKey(target)) return Denied(req, "PROTECTED_TARGET");
        if (!int.TryParse(a.GetValueOrDefault("ttl_seconds"), out int ttl) || ttl < 1 || ttl > MaxTtlSeconds)
            return Denied(req, "INVALID_TTL");
        long active = (long)_db.Scalar(
            "SELECT COUNT(*) FROM broker_intents WHERE command='SimulateNetworkBlock' AND state='APPLIED' AND expires_ms>?", now)!;
        if (active >= MaxActiveBlocks) return Denied(req, "ACTIVE_BLOCK_LIMIT");
        return Apply(req, now, "SimulateNetworkBlock", decisionId, idem, target, null, now + ttl * 1000L,
            Json(new { effect = "none (simulation)", wouldAdd = "dynamic-session WFP filter", ttl_seconds = ttl }));
    }

    private BrokerResponse Quarantine(BrokerRequest req, long now)
    {
        var a = req.Args;
        if (!Common(req, now, out var deny, out var decisionId, out var idem, out var target)) return deny!;
        var sha = (a.GetValueOrDefault("sha256") ?? "").ToLowerInvariant();
        var path = a.GetValueOrDefault("path");
        if (!IdentityKeys.IsSha256(sha)) return Denied(req, "INVALID_SHA256");
        if (!_indicators.TryGetValue(sha, out var ind) || now >= ind.ValidUntilMs)
            return Denied(req, "NO_VALID_SIGNED_INDICATOR");
        if (_protected.IsProtectedPath(path)) return Denied(req, "PROTECTED_TARGET");
        var probe = _probe.Probe(path!);
        if (probe is null) return Denied(req, "HANDLE_BINDING_UNAVAILABLE");
        if (!StringComparer.Ordinal.Equals(probe.FileIdentityKey, target)) return Denied(req, "FILE_IDENTITY_CHANGED");
        if (!StringComparer.OrdinalIgnoreCase.Equals(probe.Sha256, sha)) return Denied(req, "FILE_HASH_CHANGED");
        if (probe.SignedByProtectedPublisher) return Denied(req, "PROTECTED_PUBLISHER");
        return Apply(req, now, "SimulateQuarantine", decisionId, idem, target, sha, null,
            Json(new { effect = "none (simulation)", wouldDo = "restricted move with restore token; never delete", indicator = ind.IndicatorId }));
    }

    private bool Common(BrokerRequest req, long now, out BrokerResponse? deny, out string decisionId,
        out string idem, out string target)
    {
        var a = req.Args;
        decisionId = a.GetValueOrDefault("decision_id") ?? "";
        idem = a.GetValueOrDefault("idempotency_key") ?? "";
        target = a.GetValueOrDefault("target_key") ?? "";
        deny = null;
        if (decisionId.Length is 0 or > 64 || idem.Length is 0 or > 128 || target.Length is 0 or > 512)
            deny = Denied(req, "MISSING_ARGUMENT");
        else if (!StringComparer.Ordinal.Equals(a.GetValueOrDefault("device_id"), _deviceId))
            deny = Denied(req, "OUTSIDE_AUTHORIZED_SCOPE");
        else if (_policySha256 is null || now >= _policyExpiresMs)
            deny = Denied(req, "POLICY_NOT_VERIFIED");
        else if (!StringComparer.OrdinalIgnoreCase.Equals(a.GetValueOrDefault("policy_sha256"), _policySha256))
            deny = Denied(req, "POLICY_MISMATCH");
        else if ((long)_db.Scalar("SELECT COUNT(*) FROM broker_intents WHERE created_ms>?", now - 60_000)! >= MaxActionsPerMinute
                 && _db.Scalar("SELECT 1 FROM broker_intents WHERE idempotency_key=?", idem) is null)
            deny = Denied(req, "RATE_LIMITED");
        return deny is null;
    }

    private BrokerResponse Apply(BrokerRequest req, long now, string command, string decisionId, string idem,
        string target, string? sha, long? expiresMs, string detailJson)
    {
        // Idempotent: a repeated key returns the first outcome and performs nothing.
        var prior = _db.Query(
            "SELECT action_id,state,rollback_token,expires_ms,command,target_key FROM broker_intents WHERE idempotency_key=?", idem)
            .FirstOrDefault();
        if (prior is not null)
        {
            if ((string)prior[4]! != command || (string)prior[5]! != target) return Denied(req, "IDEMPOTENCY_KEY_REUSED");
            return new BrokerResponse(req.RequestId, (string)prior[1]! is "APPLIED" or "EXPIRED" or "ROLLED_BACK",
                "IDEMPOTENT_REPLAY", (string)prior[0]!, (string?)prior[2], (string)prior[1]!, (long?)prior[3]);
        }
        var actionId = Guid.NewGuid().ToString();
        _db.Execute(
            "INSERT INTO broker_intents(action_id,idempotency_key,decision_id,command,device_id,target_key,target_sha256,state,simulated,created_ms,updated_ms,expires_ms,detail_json) VALUES(?,?,?,?,?,?,?,'INTENDED',1,?,?,?,?)",
            actionId, idem, decisionId, command, _deviceId, target, sha, now, now, expiresMs, detailJson);
        _audit.Append(now, "INTENT", Json(new { actionId, command, target, decisionId }));
        Crash("after-intent");

        // << An enforcing build would call its effector here. The beta has none. >>
        Crash("after-effect");

        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        _db.Execute("UPDATE broker_intents SET state='APPLIED', rollback_token=?, updated_ms=? WHERE action_id=?", token, now, actionId);
        _audit.Append(now, "APPLIED_SIMULATED", Json(new { actionId, expiresMs }));
        return new BrokerResponse(req.RequestId, true, "APPLIED_SIMULATED", actionId, token, "APPLIED", expiresMs);
    }

    private BrokerResponse Rollback(BrokerRequest req, long now)
    {
        var token = req.Args.GetValueOrDefault("rollback_token") ?? "";
        var row = _db.Query("SELECT action_id,state FROM broker_intents WHERE rollback_token=?", token).FirstOrDefault();
        if (token.Length == 0 || row is null) return Denied(req, "UNKNOWN_ROLLBACK_TOKEN");
        var (id, state) = ((string)row[0]!, (string)row[1]!);
        if (state == "ROLLED_BACK") return new BrokerResponse(req.RequestId, true, "ALREADY_ROLLED_BACK", id, token, state);
        _db.Execute("UPDATE broker_intents SET state='ROLLED_BACK', updated_ms=? WHERE action_id=?", now, id);
        _audit.Append(now, "ROLLED_BACK", Json(new { actionId = id, priorState = state }));
        return new BrokerResponse(req.RequestId, true, "ROLLED_BACK", id, token, "ROLLED_BACK");
    }

    /// <summary>Expires TTL-bound actions. Call periodically.</summary>
    public int SweepExpired()
    {
        lock (_gate)
        {
            long now = _clock();
            int n = _db.Execute(
                "UPDATE broker_intents SET state='EXPIRED', updated_ms=? WHERE state='APPLIED' AND expires_ms IS NOT NULL AND expires_ms<=?", now, now);
            if (n > 0) _audit.Append(now, "EXPIRED", Json(new { count = n }));
            return n;
        }
    }

    /// <summary>
    /// Crash recovery, run at start. An intent with no recorded effect is never
    /// re-applied automatically: it fails closed to "nothing was done".
    /// </summary>
    private void Recover()
    {
        long now = _clock();
        int orphaned = _db.Execute("UPDATE broker_intents SET state='FAILED_ON_CRASH', updated_ms=? WHERE state='INTENDED'", now);
        int expired = _db.Execute(
            "UPDATE broker_intents SET state='EXPIRED', updated_ms=? WHERE state='APPLIED' AND expires_ms IS NOT NULL AND expires_ms<=?", now, now);
        long active = (long)_db.Scalar("SELECT COUNT(*) FROM broker_intents WHERE state='APPLIED'")!;
        _audit.Append(now, "BROKER_START", Json(new { orphaned, expired, active, mode = "simulation" }));
    }

    public string StatusJson()
    {
        var counts = _db.Query("SELECT state, COUNT(*) FROM broker_intents GROUP BY state")
            .ToDictionary(r => (string)r[0]!, r => (long)r[1]!);
        return Json(new { mode = "simulation", policyVerified = _policySha256 is not null && _clock() < _policyExpiresMs,
            indicators = _indicators.Count, intents = counts, auditHead = _audit.Head() });
    }

    public IReadOnlyList<object?[]> Intents() =>
        _db.Query("SELECT action_id,command,target_key,state,expires_ms,rollback_token FROM broker_intents ORDER BY created_ms, rowid");

    private void Crash(string step)
    {
        if (FaultInjector?.Invoke(step) == true) throw new BrokerCrashException(step);
    }

    private BrokerResponse Denied(BrokerRequest req, string code)
    {
        _audit.Append(_clock(), "DENIED", Json(new { code, command = req.Command, requestId = req.RequestId }));
        return new BrokerResponse(req.RequestId, false, code);
    }

    private byte[] Reply(BrokerResponse r) => FrameCodec.Seal(_sessionKey, FrameCodec.Encode(r));
    private long Kv(string key) => _db.Scalar("SELECT value FROM broker_kv WHERE key=?", key) as long? ?? 0;
    private void SetKv(string key, long value) => _db.Execute(
        "INSERT INTO broker_kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value);
    private static string Json(object o) => JsonSerializer.Serialize(o);
    public void Dispose() => _db.Dispose();
}

public sealed class BrokerCrashException(string step) : Exception("Injected broker crash at " + step);
