using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Hannibal.Core.Identity;

/// <summary>
/// Deterministic identity keys. A PID alone is never an identity (PIDs are
/// reused within minutes); a path alone is never a file identity.
/// </summary>
public static class IdentityKeys
{
    public static string Process(string bootId, int pid, long createTimeFiletime, string imageFileId)
    {
        Require(bootId, nameof(bootId)); Require(imageFileId, nameof(imageFileId));
        if (pid <= 0 || createTimeFiletime <= 0) throw new ArgumentException("Invalid process identity");
        return string.Create(CultureInfo.InvariantCulture, $"proc|{bootId}|{pid}|{createTimeFiletime}|{imageFileId}");
    }

    /// <summary>volumeSerial + 128-bit file id (FILE_ID_INFO), both hex.</summary>
    public static string FileOccurrence(string volumeSerialHex, string fileId128Hex)
    {
        Require(volumeSerialHex, nameof(volumeSerialHex)); Require(fileId128Hex, nameof(fileId128Hex));
        return $"file|{volumeSerialHex.ToLowerInvariant()}|{fileId128Hex.ToLowerInvariant()}";
    }

    public static string FileArtifact(string sha256)
    {
        if (!IsSha256(sha256)) throw new ArgumentException("Not a SHA-256 hex digest");
        return "sha256|" + sha256.ToLowerInvariant();
    }

    public static string Endpoint(string protocol, IPAddress address, int port)
    {
        if (protocol is not ("tcp" or "udp")) throw new ArgumentException("Unsupported protocol");
        if (port is < 1 or > 65535) throw new ArgumentException("Invalid port");
        string fam = address.AddressFamily == AddressFamily.InterNetworkV6 ? "v6" : "v4";
        return $"{protocol}|{fam}|{address}|{port}|{Scope(address)}";
    }

    public static bool TryParseEndpoint(string key, out string protocol, out IPAddress address, out int port)
    {
        protocol = ""; address = IPAddress.None; port = 0;
        var p = key.Split('|');
        if (p.Length != 5 || p[0] is not ("tcp" or "udp")) return false;
        if (!IPAddress.TryParse(p[2], out var ip) || !int.TryParse(p[3], NumberStyles.None, CultureInfo.InvariantCulture, out port)) return false;
        if (port is < 1 or > 65535) return false;
        protocol = p[0]; address = ip;
        // Reject non-canonical spellings so one endpoint has exactly one key.
        return Endpoint(protocol, ip, port) == key;
    }

    public static string Persistence(string axis, string location) => $"persist|{axis}|{location.ToLowerInvariant()}";

    public static string Scope(IPAddress a)
    {
        if (IPAddress.IsLoopback(a)) return "loopback";
        if (a.AddressFamily == AddressFamily.InterNetworkV6)
            return a.IsIPv6LinkLocal ? "link-local" : a.IsIPv6Multicast ? "multicast"
                 : (a.GetAddressBytes()[0] & 0xFE) == 0xFC ? "private" : "global";
        var b = a.GetAddressBytes();
        if (b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)) return "private";
        if (b[0] == 169 && b[1] == 254) return "link-local";
        if (b[0] is >= 224 and <= 239) return "multicast";
        if (b[0] == 255 || b[0] == 0) return "reserved";
        return "global";
    }

    public static bool IsSha256(string? s) =>
        s is { Length: 64 } && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static void Require(string v, string name)
    {
        if (string.IsNullOrWhiteSpace(v) || v.Contains('|')) throw new ArgumentException("Invalid identity part", name);
    }
}
