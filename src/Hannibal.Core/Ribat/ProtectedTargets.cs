using System.Net;
using Hannibal.Core.Identity;

namespace Hannibal.Core.Ribat;

/// <summary>
/// Targets that automatic containment must never touch. Applied by the policy
/// side AND re-derived independently by the broker. The lists are conservative
/// defaults; DNS, captive-portal, gateway and emergency connectivity
/// allowlisting still has to be tested on real networks before any enforcement.
/// </summary>
public sealed class ProtectedTargets
{
    private static readonly int[] ProtectedPorts = [53, 67, 68, 123, 546, 547, 853, 5353];
    private readonly HashSet<IPAddress> _extraAddresses = [];
    private readonly List<string> _protectedPathPrefixes = [];

    public ProtectedTargets(IEnumerable<IPAddress>? gatewayAndDnsServers = null, IEnumerable<string>? protectedPathPrefixes = null)
    {
        foreach (var a in gatewayAndDnsServers ?? []) _extraAddresses.Add(a);
        _protectedPathPrefixes.AddRange(protectedPathPrefixes ?? DefaultPathPrefixes);
    }

    public static readonly string[] DefaultPathPrefixes =
    [
        @"C:\Windows\", @"C:\Program Files\WindowsApps\", @"C:\Program Files\Windows Defender\",
        @"C:\ProgramData\Microsoft\Windows Defender\", @"C:\Program Files\Hannibal Protocol\",
        @"C:\ProgramData\Hannibal\", @"C:\$Recycle.Bin\", @"C:\System Volume Information\",
        @"C:\pagefile.sys", @"C:\hiberfil.sys", @"C:\swapfile.sys", @"C:\bootmgr"
    ];

    public bool IsProtectedEndpointKey(string endpointKey)
    {
        if (!IdentityKeys.TryParseEndpoint(endpointKey, out _, out var ip, out var port)) return true; // unparseable => never contain
        return IdentityKeys.Scope(ip) != "global" || ProtectedPorts.Contains(port) || _extraAddresses.Contains(ip);
    }

    public bool IsProtectedPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return true;
        var p = path.Replace('/', '\\');
        if (p.Contains("..\\", StringComparison.Ordinal) || p.StartsWith(@"\\", StringComparison.Ordinal)) return true; // traversal / UNC / device paths
        return _protectedPathPrefixes.Any(pre => p.StartsWith(pre, StringComparison.OrdinalIgnoreCase));
    }
}
