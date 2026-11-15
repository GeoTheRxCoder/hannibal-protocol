using System.Security.Cryptography;
using System.Text.Json;

namespace Hannibal.Core.Crypto;

public sealed record TrustedKey(string KeyId, string Algorithm, byte[] SubjectPublicKeyInfo);

/// <summary>Pinned keys shipped inside the signed installer. Never loaded from the bundle itself.</summary>
public sealed record TrustRoot(IReadOnlyList<TrustedKey> Keys, int Threshold)
{
    public static string ComputeKeyId(byte[] spki) => Convert.ToHexStringLower(SHA256.HashData(spki))[..16];

    public static TrustRoot Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var keys = new List<TrustedKey>();
        foreach (var k in doc.RootElement.GetProperty("keys").EnumerateArray())
        {
            var spki = Convert.FromBase64String(k.GetProperty("spki_b64").GetString()!);
            var alg = k.GetProperty("alg").GetString()!;
            var id = ComputeKeyId(spki);
            if (k.TryGetProperty("keyid", out var declared) && declared.GetString() != id)
                throw new FormatException("Trust root key id does not match key material");
            keys.Add(new TrustedKey(id, alg, spki));
        }
        int threshold = doc.RootElement.GetProperty("threshold").GetInt32();
        if (keys.Count == 0 || threshold < 1 || threshold > keys.Count)
            throw new FormatException("Invalid trust root threshold");
        return new TrustRoot(keys, threshold);
    }
}

public enum BundleFailure
{
    None, Malformed, TooLarge, UnknownKeyOrBadSignature, ThresholdNotMet,
    TypeMismatch, NotYetValid, Expired, Rollback
}

public sealed record VerifiedBundle(
    string BundleType, string BundleId, long Version, long IssuedMs, long ExpiresMs,
    string Sha256, JsonElement Payload);

public sealed record BundleResult(BundleFailure Failure, VerifiedBundle? Bundle)
{
    public bool Ok => Failure == BundleFailure.None && Bundle is not null;
}

/// <summary>
/// "Logistics" (Hatshepsut motif): everything that enters the product from
/// outside - policy, indicators, models - arrives as a signed, versioned,
/// expiring bundle. Simplified from The Update Framework: pinned root keys, a
/// signature threshold, expiry against freeze attacks and a monotonic version
/// against rollback. It is NOT a full TUF client (no delegated roles).
///
/// Signatures are detached and cover the exact bytes of the bundle file, so
/// no JSON canonicalization is involved.
/// </summary>
public static class SignedBundleVerifier
{
    public const int MaxBundleBytes = 8 * 1024 * 1024;
    public const string AlgEcdsa = "ecdsa-p256-sha256";
    public const string AlgMlDsa65 = "ml-dsa-65";

    public static BundleResult Verify(
        ReadOnlySpan<byte> bundleBytes, string signatureJson, TrustRoot root,
        string expectedType, long nowMs, long lastAcceptedVersion)
    {
        if (bundleBytes.Length == 0) return Fail(BundleFailure.Malformed);
        if (bundleBytes.Length > MaxBundleBytes) return Fail(BundleFailure.TooLarge);

        var valid = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            using var sigDoc = JsonDocument.Parse(signatureJson);
            foreach (var s in sigDoc.RootElement.GetProperty("signatures").EnumerateArray())
            {
                var keyId = s.GetProperty("keyid").GetString();
                var alg = s.GetProperty("alg").GetString();
                var sig = Convert.FromBase64String(s.GetProperty("sig").GetString()!);
                var key = root.Keys.FirstOrDefault(k => k.KeyId == keyId && k.Algorithm == alg);
                if (key is not null && VerifyOne(key, bundleBytes, sig)) valid.Add(key.KeyId);
            }
        }
        catch (Exception e) when (e is JsonException or FormatException or KeyNotFoundException or InvalidOperationException)
        {
            return Fail(BundleFailure.Malformed);
        }
        if (valid.Count == 0) return Fail(BundleFailure.UnknownKeyOrBadSignature);
        if (valid.Count < root.Threshold) return Fail(BundleFailure.ThresholdNotMet);

        // Only parse the content AFTER the signature threshold is met.
        try
        {
            using var doc = JsonDocument.Parse(bundleBytes.ToArray());
            var r = doc.RootElement;
            var type = r.GetProperty("bundle_type").GetString()!;
            var id = r.GetProperty("bundle_id").GetString()!;
            long version = r.GetProperty("version").GetInt64();
            long issued = r.GetProperty("issued_ms").GetInt64();
            long expires = r.GetProperty("expires_ms").GetInt64();
            if (string.IsNullOrWhiteSpace(id) || version < 1 || expires <= issued) return Fail(BundleFailure.Malformed);
            if (type != expectedType) return Fail(BundleFailure.TypeMismatch);
            if (nowMs < issued - 300_000) return Fail(BundleFailure.NotYetValid);
            if (nowMs >= expires) return Fail(BundleFailure.Expired);
            if (version < lastAcceptedVersion) return Fail(BundleFailure.Rollback);
            var sha = Convert.ToHexStringLower(SHA256.HashData(bundleBytes));
            return new BundleResult(BundleFailure.None, new VerifiedBundle(
                type, id, version, issued, expires, sha, r.GetProperty("payload").Clone()));
        }
        catch (Exception e) when (e is JsonException or FormatException or KeyNotFoundException or InvalidOperationException)
        {
            return Fail(BundleFailure.Malformed);
        }
    }

    private static bool VerifyOne(TrustedKey key, ReadOnlySpan<byte> data, byte[] sig)
    {
        try
        {
            if (key.Algorithm == AlgEcdsa)
            {
                using var ec = ECDsa.Create();
                ec.ImportSubjectPublicKeyInfo(key.SubjectPublicKeyInfo, out _);
                return ec.VerifyData(data, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            }
            if (key.Algorithm == AlgMlDsa65) return VerifyMlDsa(key.SubjectPublicKeyInfo, data, sig);
            return false;
        }
        catch (CryptographicException) { return false; }
    }

    private static bool VerifyMlDsa(byte[] spki, ReadOnlySpan<byte> data, byte[] sig)
    {
#if NET10_0_OR_GREATER
        if (!MLDsa.IsSupported) return false; // an unsupported platform never counts toward the threshold
        // The SPKI import is still flagged experimental (SYSLIB5006) in .NET 10.0.1xx
        // while the X.509 encodings settle. Re-check when the SDK is updated.
#pragma warning disable SYSLIB5006
        using var k = MLDsa.ImportSubjectPublicKeyInfo(spki);
#pragma warning restore SYSLIB5006
        return k.VerifyData(data, sig);
#else
        return false;
#endif
    }

    private static BundleResult Fail(BundleFailure f) => new(f, null);
}
