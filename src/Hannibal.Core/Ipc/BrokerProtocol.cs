using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Hannibal.Core.Ipc;

/// <summary>The ENTIRE broker surface. There is no generic command runner.</summary>
public enum BrokerCommand { GetStatus, SimulateNetworkBlock, SimulateQuarantine, Rollback }

public sealed record BrokerRequest(
    [property: JsonPropertyName("v")] int ProtocolVersion,
    [property: JsonPropertyName("request_id")] string RequestId,
    [property: JsonPropertyName("counter")] long Counter,
    [property: JsonPropertyName("issued_ms")] long IssuedMs,
    [property: JsonPropertyName("expires_ms")] long ExpiresMs,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("command")] string Command,
    [property: JsonPropertyName("args")] Dictionary<string, string> Args);

public sealed record BrokerResponse(
    [property: JsonPropertyName("request_id")] string RequestId,
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("action_id")] string? ActionId = null,
    [property: JsonPropertyName("rollback_token")] string? RollbackToken = null,
    [property: JsonPropertyName("state")] string? State = null,
    [property: JsonPropertyName("expires_ms")] long? ExpiresMs = null,
    [property: JsonPropertyName("simulated")] bool Simulated = true);

/// <summary>
/// Frame = u32 little-endian length | HMAC-SHA256(key, body) | body (UTF-8 JSON).
/// The MAC covers the exact body bytes. Maximum frame 64 KiB.
/// </summary>
public static class FrameCodec
{
    public const int MaxFrame = 64 * 1024;
    private const int MacLen = 32;

    public static byte[] Seal(byte[] key, ReadOnlySpan<byte> body)
    {
        if (body.Length + MacLen > MaxFrame) throw new InvalidDataException("Frame too large");
        var frame = new byte[4 + MacLen + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)(MacLen + body.Length));
        HMACSHA256.HashData(key, body, frame.AsSpan(4, MacLen));
        body.CopyTo(frame.AsSpan(4 + MacLen));
        return frame;
    }

    /// <summary>Returns the authenticated body, or null if the frame is malformed or the MAC is wrong.</summary>
    public static byte[]? Open(byte[] key, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 4 + MacLen) return null;
        uint len = BinaryPrimitives.ReadUInt32LittleEndian(frame);
        if (len > MaxFrame || len < MacLen || frame.Length != 4 + len) return null;
        var mac = frame.Slice(4, MacLen);
        var body = frame[(4 + MacLen)..];
        Span<byte> expect = stackalloc byte[MacLen];
        HMACSHA256.HashData(key, body, expect);
        return CryptographicOperations.FixedTimeEquals(mac, expect) ? body.ToArray() : null;
    }

    public static async Task<byte[]?> ReadFrameAsync(Stream s, CancellationToken ct)
    {
        var head = new byte[4];
        if (!await ReadExact(s, head, ct)) return null;
        uint len = BinaryPrimitives.ReadUInt32LittleEndian(head);
        if (len > MaxFrame || len < MacLen) return null;
        var rest = new byte[len];
        if (!await ReadExact(s, rest, ct)) return null;
        var frame = new byte[4 + len];
        head.CopyTo(frame, 0); rest.CopyTo(frame, 4);
        return frame;
    }

    private static async Task<bool> ReadExact(Stream s, byte[] buf, CancellationToken ct)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(off), ct);
            if (n == 0) return false;
            off += n;
        }
        return true;
    }

    public static byte[] Encode<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value);

    public static T? Decode<T>(byte[] body) where T : class
    {
        try { return JsonSerializer.Deserialize<T>(body); }
        catch (JsonException) { return null; }
    }
}

/// <summary>Rejects expired, long-lived, replayed or out-of-order requests.</summary>
public sealed class ReplayGuard(long maxLifetimeMs = 30_000, long clockSkewMs = 5_000)
{
    private readonly Dictionary<string, long> _nonces = new(StringComparer.Ordinal);
    private long _lastCounter;

    public long LastCounter { get => _lastCounter; init => _lastCounter = value; }

    public string? Check(BrokerRequest r, long nowMs)
    {
        if (r.ProtocolVersion != 1) return "UNSUPPORTED_PROTOCOL";
        if (string.IsNullOrWhiteSpace(r.RequestId) || r.Nonce is not { Length: 32 }) return "MALFORMED_REQUEST";
        if (r.ExpiresMs <= r.IssuedMs || r.ExpiresMs - r.IssuedMs > maxLifetimeMs) return "INVALID_LIFETIME";
        if (nowMs < r.IssuedMs - clockSkewMs) return "ISSUED_IN_FUTURE";
        if (nowMs >= r.ExpiresMs) return "REQUEST_EXPIRED";
        if (r.Counter <= _lastCounter) return "COUNTER_REPLAY";
        foreach (var dead in _nonces.Where(kv => kv.Value <= nowMs).Select(kv => kv.Key).ToArray()) _nonces.Remove(dead);
        if (!_nonces.TryAdd(r.Nonce, r.ExpiresMs + clockSkewMs)) return "NONCE_REPLAY";
        _lastCounter = r.Counter;
        return null;
    }
}

/// <summary>Core-side client. The transport is a delegate so tests and the simulator can run in-process.</summary>
public sealed class BrokerClient(byte[] sessionKey, Func<byte[], byte[]?> transport, Func<long> clock)
{
    // Seeded from the clock so the counter stays ahead of the broker's persisted
    // high-water mark when the Core service restarts.
    private long _counter = clock();

    public BrokerResponse Send(BrokerCommand command, Dictionary<string, string> args)
    {
        long now = clock();
        var req = new BrokerRequest(1, Guid.NewGuid().ToString("N"), Interlocked.Increment(ref _counter),
            now, now + 15_000, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)),
            command.ToString(), args);
        var reply = transport(FrameCodec.Seal(sessionKey, FrameCodec.Encode(req)));
        if (reply is null) return new BrokerResponse(req.RequestId, false, "BROKER_UNAVAILABLE");
        var body = FrameCodec.Open(sessionKey, reply);
        var resp = body is null ? null : FrameCodec.Decode<BrokerResponse>(body);
        if (resp is null) return new BrokerResponse(req.RequestId, false, "BROKER_REPLY_NOT_AUTHENTIC");
        if (resp.RequestId != req.RequestId) return new BrokerResponse(req.RequestId, false, "BROKER_REPLY_MISMATCH");
        return resp;
    }

    public static string Utf8(byte[] b) => Encoding.UTF8.GetString(b);
}
